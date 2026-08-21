#include "scanner.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace airodump {
namespace {

std::string power_text(const std::optional<int> &power) {
  return power ? std::to_string(*power) : "--";
}

std::string channel_text(const std::optional<int> &channel) {
  return channel && *channel > 0 ? std::to_string(*channel) : "--";
}

void append_probe(std::string &probes, const std::string &probe) {
  if (probe.empty())
    return;
  std::istringstream in(probes);
  std::string current;
  while (std::getline(in, current, ',')) {
    if (current == probe || current == " " + probe)
      return;
  }
  if (!probes.empty())
    probes += ", ";
  probes += probe;
}

}

void Scanner::ingest(const RadioInfo &radio, const FrameInfo &frame) {
  const auto now = Clock::now();
  const std::optional<int> power =
      radio.signal_dbm ? std::optional<int>(*radio.signal_dbm) : std::nullopt;
  const int channel =
      radio.frequency_mhz ? frequency_to_channel(*radio.frequency_mhz) : 0;

  if ((frame.kind == FrameKind::Beacon ||
       frame.kind == FrameKind::ProbeResponse) &&
      frame.bssid) {
    // ap 정보 저장
    auto [it, inserted] = aps_.try_emplace(*frame.bssid);
    AccessPoint &ap = it->second;
    if (inserted)
      ap.bssid = *frame.bssid;
    if (frame.kind == FrameKind::Beacon)
      ++ap.beacons;
    ap.last_seen = now;
    if (power)
      ap.power = power;
    if (channel > 0)
      ap.channel = channel;
    if (!frame.encryption.empty())
      ap.encryption = frame.encryption;
    if (frame.essid && !frame.essid->empty())
      ap.essid = *frame.essid;
    return;
  }

  if (frame.kind == FrameKind::Data) {
    // data 개수와 station frame 개수 저장
    if (frame.bssid) {
      auto [it, inserted] = aps_.try_emplace(*frame.bssid);
      if (inserted)
        it->second.bssid = *frame.bssid;
      ++it->second.data;
      it->second.last_seen = now;
      if (channel > 0)
        it->second.channel = channel;
    }
    if (frame.station) {
      auto [it, inserted] = stations_.try_emplace(*frame.station);
      Station &station = it->second;
      if (inserted)
        station.address = *frame.station;
      ++station.frames;
      station.last_seen = now;
      station.bssid = frame.bssid;
      if (power && frame.station_transmitted)
        station.power = power;
    }
    return;
  }

  if (frame.kind == FrameKind::ProbeRequest && frame.station) {
    // ap 에 연결되지 않은 station
    auto [it, inserted] = stations_.try_emplace(*frame.station);
    Station &station = it->second;
    if (inserted)
      station.address = *frame.station;
    ++station.frames;
    station.last_seen = now;
    if (power)
      station.power = power;
    if (frame.essid && !frame.essid->empty())
      append_probe(station.probes, *frame.essid);
  }
}

void Scanner::render(const std::string &interface_name,
                      bool clear_screen) const {
  // 터미널 화면 다시 출력
  if (clear_screen)
    std::cout << "\033[2J\033[H";
  std::cout << "airodump  interface: " << interface_name
            << "  AP: " << aps_.size() << "  Stations: " << stations_.size()
            << "\n\n";
  std::cout << std::left << std::setw(19) << "BSSID" << std::right
            << std::setw(5) << "PWR" << std::setw(11) << "Beacons"
            << std::setw(9) << "#Data" << std::setw(5) << "CH" << "  "
            << std::left << std::setw(7) << "ENC" << "ESSID\n";

  std::vector<const AccessPoint *> aps;
  for (const auto &entry : aps_)
    aps.push_back(&entry.second);
  std::sort(aps.begin(), aps.end(),
            [](const AccessPoint *a, const AccessPoint *b) {
              return a->beacons > b->beacons;
            });
  for (const AccessPoint *ap : aps) {
    std::cout << std::left << std::setw(19) << ap->bssid.to_string()
              << std::right << std::setw(5) << power_text(ap->power)
              << std::setw(11) << ap->beacons << std::setw(9) << ap->data
              << std::setw(5) << channel_text(ap->channel) << "  " << std::left
              << std::setw(7) << ap->encryption << ap->essid << '\n';
  }

  std::cout << "\n"
            << std::left << std::setw(19) << "BSSID" << std::setw(19)
            << "STATION" << std::right << std::setw(5) << "PWR" << std::setw(9)
            << "Frames" << "  " << std::left << "Probes\n";
  for (const auto &entry : stations_) {
    const Station &station = entry.second;
    const std::string bssid =
        station.bssid ? station.bssid->to_string() : "(not associated)";
    std::cout << std::left << std::setw(19) << bssid << std::setw(19)
              << station.address.to_string() << std::right << std::setw(5)
              << power_text(station.power) << std::setw(9) << station.frames
              << "  " << std::left << station.probes << '\n';
  }
  std::cout << std::flush;
}

}
