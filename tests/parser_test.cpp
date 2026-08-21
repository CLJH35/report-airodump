#include "packet.hpp"
#include "scanner.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void put_mac(std::vector<std::uint8_t> &frame, std::size_t offset,
             std::initializer_list<std::uint8_t> mac) {
  std::size_t i = offset;
  for (const auto byte : mac)
    frame[i++] = byte;
}

std::vector<std::uint8_t> radio_header() {
  std::vector<std::uint8_t> radio(13, 0);
  radio[2] = 13;   // radiotap length
  radio[4] = 0x28; // channel + antenna signal fields
  radio[8] = 0x6c; // 2412 MHz, little endian
  radio[9] = 0x09;
  radio[12] = 0xd6; // -42 dBm
  return radio;
}

std::vector<std::uint8_t> beacon() {
  std::vector<std::uint8_t> frame(44, 0);
  frame[0] = 0x80;
  put_mac(frame, 16, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
  frame[34] = 0x10; // privacy capability
  frame[36] = 0;    // SSID tag
  frame[37] = 4;
  frame[38] = 't';
  frame[39] = 'e';
  frame[40] = 's';
  frame[41] = 't';
  frame[42] = 48; // RSN tag
  frame[43] = 0;
  return frame;
}

std::vector<std::uint8_t> probe_response() {
  auto frame = beacon();
  frame[0] = 0x50;
  return frame;
}

std::vector<std::uint8_t> data_from_ap() {
  std::vector<std::uint8_t> frame(24, 0);
  frame[0] = 0x08;
  frame[1] = 0x02; // From DS
  put_mac(frame, 4, {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff});
  put_mac(frame, 10, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
  return frame;
}

std::vector<std::uint8_t> probe_request() {
  std::vector<std::uint8_t> frame(31, 0);
  frame[0] = 0x40;
  put_mac(frame, 10, {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee});
  frame[24] = 0;
  frame[25] = 5;
  frame[26] = 'c';
  frame[27] = 'a';
  frame[28] = 'f';
  frame[29] = 'e';
  frame[30] = '5';
  return frame;
}

} // namespace

int main() {
  const auto raw_radio = radio_header();
  const auto radio =
      airodump::parse_radiotap(raw_radio.data(), raw_radio.size());
  assert(radio);
  assert(radio->header_length == 13);
  assert(radio->signal_dbm && *radio->signal_dbm == -42);
  assert(radio->frequency_mhz && *radio->frequency_mhz == 2412);
  assert(airodump::frequency_to_channel(2412) == 1);
  assert(airodump::frequency_to_channel(2484) == 14);
  assert(airodump::frequency_to_channel(5180) == 36);

  const auto raw_beacon = beacon();
  const auto beacon_info =
      airodump::parse_dot11(raw_beacon.data(), raw_beacon.size());
  assert(beacon_info && beacon_info->kind == airodump::FrameKind::Beacon);
  assert(beacon_info->bssid->to_string() == "00:11:22:33:44:55");
  assert(beacon_info->essid && *beacon_info->essid == "test");
  assert(beacon_info->encryption == "WPA2");

  const auto raw_response = probe_response();
  const auto response_info =
      airodump::parse_dot11(raw_response.data(), raw_response.size());
  assert(response_info &&
         response_info->kind == airodump::FrameKind::ProbeResponse);
  assert(response_info->bssid->to_string() == "00:11:22:33:44:55");
  assert(response_info->essid && *response_info->essid == "test");

  const auto raw_data = data_from_ap();
  const auto data_info =
      airodump::parse_dot11(raw_data.data(), raw_data.size());
  assert(data_info && data_info->kind == airodump::FrameKind::Data);
  assert(data_info->bssid->to_string() == "00:11:22:33:44:55");
  assert(data_info->station->to_string() == "AA:BB:CC:DD:EE:FF");
  assert(!data_info->station_transmitted);

  const auto raw_probe = probe_request();
  const auto probe_info =
      airodump::parse_dot11(raw_probe.data(), raw_probe.size());
  assert(probe_info && probe_info->kind == airodump::FrameKind::ProbeRequest);
  assert(probe_info->station->to_string() == "02:AA:BB:CC:DD:EE");
  assert(probe_info->station_transmitted);
  assert(probe_info->essid && *probe_info->essid == "cafe5");

  airodump::Scanner scanner;
  scanner.ingest(*radio, *beacon_info);
  scanner.ingest(*radio, *response_info);
  scanner.ingest(*radio, *data_info);
  scanner.ingest(*radio, *probe_info);
  assert(scanner.access_points().size() == 1);
  assert(scanner.access_points().begin()->second.beacons == 1);
  assert(scanner.access_points().begin()->second.data == 1);
  assert(scanner.stations().size() == 2);

  std::cout << "all parser tests passed\n";
  return 0;
}
