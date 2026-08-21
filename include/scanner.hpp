#pragma once

#include "packet.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace airodump {

using Clock = std::chrono::steady_clock;

struct AccessPoint {
  MacAddress bssid;
  std::uint64_t beacons = 0;
  std::uint64_t data = 0;
  std::optional<int> power;
  std::optional<int> channel;
  std::string encryption = "?";
  std::string essid = "<hidden>";
  Clock::time_point last_seen{};
};

struct Station {
  MacAddress address;
  std::optional<MacAddress> bssid;
  std::uint64_t frames = 0;
  std::optional<int> power;
  std::string probes;
  Clock::time_point last_seen{};
};

class Scanner {
public:
  void ingest(const RadioInfo &radio, const FrameInfo &frame);
  void render(const std::string &interface_name, bool clear_screen) const;

  const std::map<MacAddress, AccessPoint> &access_points() const {
    return aps_;
  }
  const std::map<MacAddress, Station> &stations() const { return stations_; }

private:
  std::map<MacAddress, AccessPoint> aps_;
  std::map<MacAddress, Station> stations_;
};

}
