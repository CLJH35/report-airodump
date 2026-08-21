#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace airodump {

struct MacAddress {
  std::array<std::uint8_t, 6> bytes{};

  bool operator<(const MacAddress &rhs) const { return bytes < rhs.bytes; }
  bool operator==(const MacAddress &rhs) const { return bytes == rhs.bytes; }
  std::string to_string() const;
};

struct RadioInfo {
  std::size_t header_length = 0;
  std::optional<std::int8_t> signal_dbm;
  std::optional<std::uint16_t> frequency_mhz;
};

enum class FrameKind { Other, Beacon, ProbeResponse, ProbeRequest, Data };

struct FrameInfo {
  FrameKind kind = FrameKind::Other;
  std::optional<MacAddress> bssid;
  std::optional<MacAddress> station;
  bool station_transmitted = false;
  std::optional<std::string> essid;
  std::string encryption;
};

std::optional<RadioInfo> parse_radiotap(const std::uint8_t *packet,
                                        std::size_t length);
std::optional<FrameInfo> parse_dot11(const std::uint8_t *frame,
                                     std::size_t length);
int frequency_to_channel(std::uint16_t frequency_mhz);

} // namespace airodump
