#include "packet.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <vector>

namespace airodump {
namespace {

std::uint16_t le16(const std::uint8_t *p) {
  return static_cast<std::uint16_t>(p[0]) |
         (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t le32(const std::uint8_t *p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

std::size_t aligned(std::size_t offset, std::size_t alignment) {
  return (offset + alignment - 1) & ~(alignment - 1);
}

MacAddress mac_at(const std::uint8_t *p) {
  // mac address 가져오기
  MacAddress result;
  std::copy(p, p + result.bytes.size(), result.bytes.begin());
  return result;
}

struct Tags {
  std::optional<std::string> ssid;
  bool rsn = false;
  bool sae = false;
  bool wpa = false;
};

Tags parse_tags(const std::uint8_t *p, std::size_t length) {
  // ssid 와 암호화 tag 확인
  Tags tags;
  std::size_t offset = 0;
  while (offset + 2 <= length) {
    const std::uint8_t id = p[offset];
    const std::size_t size = p[offset + 1];
    offset += 2;
    if (offset + size > length)
      break;

    if (id == 0) {
      std::string ssid(reinterpret_cast<const char *>(p + offset), size);
      for (char &c : ssid) {
        const unsigned char value = static_cast<unsigned char>(c);
        if (value < 32 || value == 127)
          c = '.';
      }
      tags.ssid = ssid;
    } else if (id == 48) {
      tags.rsn = true;
      // rsn 안에 있는 akm 확인
      if (size >= 8) {
        std::size_t pos = offset + 2 + 4;
        const std::size_t end = offset + size;
        if (pos + 2 <= end) {
          const std::uint16_t pairwise_count = le16(p + pos);
          pos += 2 + static_cast<std::size_t>(pairwise_count) * 4;
          if (pos + 2 <= end) {
            const std::uint16_t akm_count = le16(p + pos);
            pos += 2;
            for (std::uint16_t i = 0; i < akm_count && pos + 4 <= end;
                 ++i, pos += 4) {
              const bool ieee_oui =
                  p[pos] == 0x00 && p[pos + 1] == 0x0f && p[pos + 2] == 0xac;
              if (ieee_oui &&
                  (p[pos + 3] == 8 || p[pos + 3] == 9 || p[pos + 3] == 18)) {
                tags.sae = true;
              }
            }
          }
        }
      }
    } else if (id == 221 && size >= 4 && p[offset] == 0x00 &&
               p[offset + 1] == 0x50 && p[offset + 2] == 0xf2 &&
               p[offset + 3] == 0x01) {
      tags.wpa = true;
    }
    offset += size;
  }
  return tags;
}

}

std::string MacAddress::to_string() const {
  std::ostringstream out;
  out << std::uppercase << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i != 0)
      out << ':';
    out << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return out.str();
}

std::optional<RadioInfo> parse_radiotap(const std::uint8_t *packet,
                                         std::size_t length) {
  // radiotap 길이 확인
  if (packet == nullptr || length < 8 || packet[0] != 0)
    return std::nullopt;

  RadioInfo result;
  result.header_length = le16(packet + 2);
  if (result.header_length < 8 || result.header_length > length)
    return std::nullopt;

  std::vector<std::uint32_t> present;
  std::size_t word_offset = 4;
  do {
    if (word_offset + 4 > result.header_length)
      return std::nullopt;
    present.push_back(le32(packet + word_offset));
    word_offset += 4;
  } while ((present.back() & 0x80000000U) != 0 && present.size() < 16);

  if ((present.back() & 0x80000000U) != 0)
    return std::nullopt;
  const std::uint32_t fields = present.front();
  std::size_t offset = word_offset;

  auto take = [&](unsigned bit, std::size_t alignment,
                  std::size_t size) -> const std::uint8_t * {
    if ((fields & (1U << bit)) == 0)
      return nullptr;
    offset = aligned(offset, alignment);
    if (offset + size > result.header_length) {
      offset = result.header_length + 1;
      return nullptr;
    }
    const std::uint8_t *value = packet + offset;
    offset += size;
    return value;
  };

  take(0, 8, 8); // tsft
  take(1, 1, 1); // flags
  take(2, 1, 1); // rate
  if (const std::uint8_t *channel = take(3, 2, 4)) {
    result.frequency_mhz = le16(channel);
  }
  take(4, 2, 2); // fhss
  if (const std::uint8_t *signal = take(5, 1, 1)) {
    result.signal_dbm = static_cast<std::int8_t>(*signal);
  }
  if (offset > result.header_length)
    return std::nullopt;
  return result;
}

std::optional<FrameInfo> parse_dot11(const std::uint8_t *frame,
                                     std::size_t length) {
  if (frame == nullptr || length < 24)
    return std::nullopt;
  const std::uint16_t fc = le16(frame);
  const unsigned type = (fc >> 2) & 0x3;
  const unsigned subtype = (fc >> 4) & 0xf;
  const bool to_ds = (fc & 0x0100) != 0;
  const bool from_ds = (fc & 0x0200) != 0;

  FrameInfo result;
  // beacon 이랑 probe response 는 ap 정보가 들어있음
  if (type == 0 && (subtype == 8 || subtype == 5)) {
    if (length < 36)
      return std::nullopt;
    result.kind = subtype == 8 ? FrameKind::Beacon : FrameKind::ProbeResponse;
    result.bssid = mac_at(frame + 16);
    const std::uint16_t capability = le16(frame + 34);
    const Tags tags = parse_tags(frame + 36, length - 36);
    result.essid = tags.ssid;
    if (tags.sae) {
      result.encryption = "WPA3";
    } else if (tags.rsn) {
      result.encryption = "WPA2";
    } else if (tags.wpa) {
      result.encryption = "WPA";
    } else if ((capability & 0x0010) != 0) {
      result.encryption = "WEP";
    } else {
      result.encryption = "OPN";
    }
  } else if (type == 0 && subtype == 4) {
    // 연결 안 된 station 도 찾기
    result.kind = FrameKind::ProbeRequest;
    result.station = mac_at(frame + 10);
    result.station_transmitted = true;
    result.essid = parse_tags(frame + 24, length - 24).ssid;
  } else if (type == 2) {
    // to ds, from ds 에 따라 주소 위치가 다름
    result.kind = FrameKind::Data;
    if (to_ds && !from_ds) {
      result.bssid = mac_at(frame + 4);
      result.station = mac_at(frame + 10);
      result.station_transmitted = true;
    } else if (!to_ds && from_ds) {
      result.bssid = mac_at(frame + 10);
      result.station = mac_at(frame + 4);
    } else if (!to_ds && !from_ds) {
      result.bssid = mac_at(frame + 16);
      result.station = mac_at(frame + 10);
      result.station_transmitted = true;
    }
  }
  return result;
}

int frequency_to_channel(std::uint16_t frequency) {
  if (frequency == 2484)
    return 14;
  if (frequency >= 2412 && frequency <= 2472)
    return (frequency - 2407) / 5;
  if (frequency >= 5000 && frequency <= 5895)
    return (frequency - 5000) / 5;
  if (frequency >= 5955 && frequency <= 7115)
    return (frequency - 5950) / 5;
  return 0;
}

}
