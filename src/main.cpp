#include "packet.hpp"
#include "scanner.hpp"

#include <pcap/pcap.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

void handle_signal(int) { stop_requested = 1; }

struct Options {
  std::string interface_name;
  std::vector<int> channels;
  int hop_milliseconds = 500;
  bool clear_screen = true;
};

void print_usage(const char *program) {
  std::cout << "syntax : " << program << " <interface> [options]\n"
            << "sample : " << program << " mon0\n\n"
            << "options:\n"
            << "  --channels 1,6,11   enable channel hopping\n"
            << "  --hop-ms 500        hopping interval in milliseconds\n"
            << "  --no-clear          do not clear terminal between updates\n"
            << "  -h, --help          show this help\n";
}

int parse_integer(const std::string &value, const std::string &option) {
  std::size_t consumed = 0;
  int result = 0;
  try {
    result = std::stoi(value, &consumed);
  } catch (const std::exception &) {
    throw std::runtime_error(option + ": invalid number: " + value);
  }
  if (consumed != value.size()) {
    throw std::runtime_error(option + ": invalid number: " + value);
  }
  return result;
}

std::vector<int> parse_channels(const std::string &value) {
  std::vector<int> channels;
  std::istringstream input(value);
  std::string item;
  while (std::getline(input, item, ',')) {
    const int channel = parse_integer(item, "--channels");
    if (channel < 1 || channel > 233) {
      throw std::runtime_error("--channels: channel must be between 1 and 233");
    }
    channels.push_back(channel);
  }
  if (channels.empty())
    throw std::runtime_error("--channels: list cannot be empty");
  return channels;
}

Options parse_options(int argc, char **argv) {
  if (argc < 2)
    throw std::runtime_error("missing interface");
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "-h" || argument == "--help") {
      print_usage(argv[0]);
      std::exit(0);
    } else if (argument == "--channels") {
      if (++i >= argc)
        throw std::runtime_error("--channels requires a value");
      options.channels = parse_channels(argv[i]);
    } else if (argument == "--hop-ms") {
      if (++i >= argc)
        throw std::runtime_error("--hop-ms requires a value");
      options.hop_milliseconds = parse_integer(argv[i], "--hop-ms");
      if (options.hop_milliseconds < 100 || options.hop_milliseconds > 60000) {
        throw std::runtime_error("--hop-ms must be between 100 and 60000");
      }
    } else if (argument == "--no-clear") {
      options.clear_screen = false;
    } else if (!argument.empty() && argument[0] == '-') {
      throw std::runtime_error("unknown option: " + argument);
    } else if (options.interface_name.empty()) {
      options.interface_name = argument;
    } else {
      throw std::runtime_error("only one interface may be specified");
    }
  }
  if (options.interface_name.empty())
    throw std::runtime_error("missing interface");
  return options;
}

bool safe_interface_name(const std::string &name) {
  if (name.empty())
    return false;
  for (const unsigned char c : name) {
    if (!(std::isalnum(c) || c == '_' || c == '-' || c == '.'))
      return false;
  }
  return true;
}

bool set_channel(const std::string &interface_name, int channel) {
  // Both values were strictly validated while parsing the command line.
  const std::string command = "iw dev " + interface_name + " set channel " +
                              std::to_string(channel) + " >/dev/null 2>&1";
  return std::system(command.c_str()) == 0;
}

class ChannelHopper {
public:
  ChannelHopper(std::string interface_name, std::vector<int> channels,
                int interval_ms)
      : interface_name_(std::move(interface_name)),
        channels_(std::move(channels)), interval_ms_(interval_ms) {
    if (!channels_.empty())
      worker_ = std::thread([this] { run(); });
  }

  ~ChannelHopper() {
    stopped_.store(true);
    if (worker_.joinable())
      worker_.join();
  }

private:
  void run() {
    std::size_t index = 0;
    while (!stopped_.load() && !stop_requested) {
      set_channel(interface_name_, channels_[index]);
      index = (index + 1) % channels_.size();
      const int slices = std::max(1, interval_ms_ / 50);
      for (int i = 0; i < slices && !stopped_.load() && !stop_requested; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
    }
  }

  std::string interface_name_;
  std::vector<int> channels_;
  int interval_ms_;
  std::atomic<bool> stopped_{false};
  std::thread worker_;
};

struct PcapDeleter {
  void operator()(pcap_t *handle) const {
    if (handle)
      pcap_close(handle);
  }
};

std::unique_ptr<pcap_t, PcapDeleter>
open_capture(const std::string &interface_name) {
  char error[PCAP_ERRBUF_SIZE]{};
  pcap_t *raw = pcap_create(interface_name.c_str(), error);
  if (!raw)
    throw std::runtime_error(error);
  std::unique_ptr<pcap_t, PcapDeleter> handle(raw);

  if (pcap_set_snaplen(raw, 65535) != 0 || pcap_set_promisc(raw, 1) != 0 ||
      pcap_set_timeout(raw, 250) != 0) {
    throw std::runtime_error(pcap_geterr(raw));
  }
  const int activation = pcap_activate(raw);
  if (activation < 0)
    throw std::runtime_error(pcap_geterr(raw));
  if (activation > 0)
    std::cerr << "pcap warning: " << pcap_geterr(raw) << '\n';

  // Some Linux capture drivers do not return from pcap_next_ex() until the
  // first packet arrives, even when a read timeout was configured.  Use
  // non-blocking capture so the terminal UI and signal handling stay alive on
  // quiet channels.
  if (pcap_setnonblock(raw, 1, error) != 0)
    throw std::runtime_error(error);

  if (pcap_datalink(raw) != DLT_IEEE802_11_RADIO) {
    throw std::runtime_error("interface does not provide radiotap headers; "
                             "enable monitor mode first");
  }
  return handle;
}

} // namespace

int main(int argc, char **argv) {
  try {
    const Options options = parse_options(argc, argv);
    if (!safe_interface_name(options.interface_name)) {
      throw std::runtime_error("interface contains unsupported characters");
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    auto capture = open_capture(options.interface_name);
    ChannelHopper hopper(options.interface_name, options.channels,
                         options.hop_milliseconds);
    airodump::Scanner scanner;
    auto next_render = std::chrono::steady_clock::now();
    scanner.render(options.interface_name, options.clear_screen);
    next_render =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(500);

    while (!stop_requested) {
      pcap_pkthdr *header = nullptr;
      const u_char *packet = nullptr;
      const int status = pcap_next_ex(capture.get(), &header, &packet);
      if (status == -1)
        throw std::runtime_error(pcap_geterr(capture.get()));
      if (status == -2)
        break;
      if (status == 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (status == 1 && header != nullptr) {
        const auto radio = airodump::parse_radiotap(packet, header->caplen);
        if (radio && radio->header_length < header->caplen) {
          const auto frame =
              airodump::parse_dot11(packet + radio->header_length,
                                    header->caplen - radio->header_length);
          if (frame)
            scanner.ingest(*radio, *frame);
        }
      }

      const auto now = std::chrono::steady_clock::now();
      if (now >= next_render) {
        scanner.render(options.interface_name, options.clear_screen);
        next_render = now + std::chrono::milliseconds(500);
      }
    }
    scanner.render(options.interface_name, options.clear_screen);
    std::cout << "\nStopped.\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "error: " << error.what() << "\n\n";
    print_usage(argv[0]);
    return 1;
  }
}
