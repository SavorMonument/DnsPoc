#include "dns.h"

namespace std {
std::string to_string(SectionClass sclass) {
  switch (sclass) {
  case SectionClass::IN:
    return std::string("IN");
  case SectionClass::CS:
    return std::string("CS");
  case SectionClass::CH:
    return std::string("CH");
  case SectionClass::HS:
    return std::string("HS");
  case SectionClass::ANY:
    return std::string("ANY");
  }
  return std::string();
}

std::string to_string(SectionType type) {
  switch (type) {
  case SectionType::A:
    return std::string("A");
  case SectionType::NS:
    return std::string("NS");
  case SectionType::MD:
    return std::string("MD");
  case SectionType::MF:
    return std::string("MF");
  case SectionType::CNAME:
    return std::string("CNAME");
  case SectionType::SOA:
    return std::string("SOA");
  case SectionType::MB:
    return std::string("MB");
  case SectionType::MG:
    return std::string("MG");
  case SectionType::MR:
    return std::string("MR");
  case SectionType::_NULL:
    return std::string("NULL");
  case SectionType::WKS:
    return std::string("WKS");
  case SectionType::PTR:
    return std::string("PTR");
  case SectionType::HINFO:
    return std::string("HINFO");
  case SectionType::MINFO:
    return std::string("MINFO");
  case SectionType::MX:
    return std::string("MX");
  case SectionType::TXT:
    return std::string("TXT");
  }
  return std::string();
}
} // namespace std

std::string join(const std::vector<std::string> &tokens, const std::string str) {
  std::string joined{};
  for (const auto &tok : tokens) {
    joined.append(tok);
    if (&tok != &tokens.back()) {
      joined.append(str);
    }
  }
  return joined;
}

std::string DnsPacketTcp::to_string() const {
  auto str = std::string();

  str.append("DnsPacket{id: ");
  str.append(std::to_string(this->header.id));

  str.append(", qdcount: ");
  str.append(std::to_string(this->header.qd_count));

  str.append(", ancount: ");
  str.append(std::to_string(this->header.an_count));

  str.append(", questions:");
  for (const auto &ques : this->questions) {
    str.append(" ");
    str.append(join(ques.lables, "."));
  }

  str.append(", answers:");
  for (const auto &ans : this->answers) {
    str.append(" ");
    str.append(std::to_string(ans.sclass));
    str.append(".");
    str.append(std::to_string(ans.type));
    str.append(".");
    str.append(join(ans.lables, "."));
    str.append("-");
    for (const auto &b : ans.rdata) {
      str.append(std::to_string(b));
      if (&b != &ans.rdata.back()) {
        str.append(".");
      }
    }
  }

  str.append("}");
  return str;
}

std::vector<uint8_t> DnsPacketTcp::serialize() const {
  std::vector<uint8_t> serialized{};

  rpush_bytes<uint16_t>(serialized, 0);
  

  rpush_bytes(serialized, this->header.id);
  rpush_bytes(serialized, this->header.flags);
  rpush_bytes(serialized, this->header.qd_count);
  rpush_bytes(serialized, this->header.an_count);
  rpush_bytes(serialized, this->header.ns_count);
  rpush_bytes(serialized, this->header.ar_count);

  for (const auto &question : this->questions) {
    for (const auto &lable : question.lables) {
      serialized.reserve(lable.size() + 1);
      serialized.push_back(lable.size());
      serialized.insert(serialized.end(), lable.begin(), lable.end());
    }
    serialized.push_back(0);

    rpush_bytes(serialized, question.type);
    rpush_bytes(serialized, question.qclass);
  }

  //TODO: serialize the rest of the sections

  uint16_t packet_len = serialized.size() - 2;
  serialized[1] = *(uint8_t*)&packet_len;
  serialized[0] = *((uint8_t*)&packet_len + 1);

  return serialized;
}

DnsPacketTcp DnsPacketTcp::deserialize(const uint8_t *data) {
  DnsPacketTcp packet{};
  auto cursor = data;

  // On tcp connection first two bytes are a length
  packet.length = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  data += 2;

  packet.header.id = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.flags = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.qd_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.an_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.ns_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.ar_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;

  // Parse question section
  for (int i = 0; i < packet.header.qd_count; i++) {
    auto question = DnsPacketTcp::parse_question(&cursor, data);
    packet.questions.push_back(question);
  }

  // Parse answer section
  for (int i = 0; i < packet.header.an_count; i++) {
    auto answer = DnsPacketTcp::parse_section(&cursor, data);
    if (answer.type != SectionType::A || answer.sclass != SectionClass::IN) {
      // Not implemented
      throw std::exception();
    }
    packet.answers.push_back(answer);
  }

  // Parse authority section
  for (int i = 0; i < packet.header.ns_count; i++) {
    auto authority = DnsPacketTcp::parse_section(&cursor, data);
    packet.authorities.push_back(authority);
  }

  // Parse additional section
  for (int i = 0; i < packet.header.ar_count; i++) {
    auto additional = DnsPacketTcp::parse_section(&cursor, data);
    packet.additionals.push_back(additional);
  }

  return packet;
}

inline bool DnsPacketTcp::is_name_pointer(const uint8_t val) {
  // It's a name pointer if first two bits are set
  return (val & 0xC0) == 0xC0;
}

void DnsPacketTcp::parse_name(std::vector<std::string> &name, const uint8_t **cur, const uint8_t *data) {
  auto cursor = *cur;

  while (1) {
    // Dns compression points to previous def of same name
    if (DnsPacketTcp::is_name_pointer(*cursor)) {
      auto offset = reverse_bytes<uint16_t>(cursor);
      // Unset most sig two bits that denote the pointer
      offset ^= 0xC000;

      cursor += 2;
      auto name_cursor = data + offset;
      // Jump to name pointer and continue reading name
      DnsPacketTcp::parse_name(name, &name_cursor, data);
      break;
    } else {
      uint8_t char_nr = *(cursor++);
      name.push_back(std::string(cursor, cursor + char_nr));
      cursor += char_nr;
      if (*cursor == '\0') {
        cursor++;
        break;
      }
    }
  }

  *cur = cursor;
}

DnsSection DnsPacketTcp::parse_section(const uint8_t **cur, const uint8_t *data) {
  auto section = DnsSection{};
  auto cursor = *cur;

  DnsPacketTcp::parse_name(section.lables, &cursor, data);

  section.type = static_cast<SectionType>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;
  section.sclass = static_cast<SectionClass>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;
  section.ttl = reverse_bytes<uint32_t>(cursor);
  cursor += 4;
  section.rd_length = reverse_bytes<uint16_t>(cursor);
  cursor += 2;

  section.rdata.reserve(section.rd_length);
  section.rdata.insert(section.rdata.end(), cursor, cursor + section.rd_length);
  cursor += section.rd_length;

  *cur = cursor;
  return section;
}

DnsQuestion DnsPacketTcp::parse_question(const uint8_t **cur, const uint8_t *data) {
  auto question = DnsQuestion{};
  auto cursor = *cur;

  DnsPacketTcp::parse_name(question.lables, &cursor, data);

  question.type = static_cast<SectionType>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;
  question.qclass = static_cast<SectionClass>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;

  *cur = cursor;
  return question;
}

std::vector<std::string> split(const std::string &str, const std::string &del) {
  std::vector<std::string> tokens{};

  std::size_t last_del = 0;
  std::size_t new_del = 0;
  while ((new_del = str.find(del, last_del)) != std::string::npos) {
    tokens.push_back(std::string(str.begin() + last_del, str.begin() + new_del));
    last_del = new_del + 1;
  }
  tokens.push_back(std::string(str.begin() + last_del, str.end()));

  return tokens;
}

DnsPacketTcp DnsPacketTcp::url_querry_packet(const uint16_t id, const std::string &url) {
  DnsPacketTcp packet{};

  packet.header.id = id;
  // Make request recursive
  packet.header.flags |= 0x1 << 8;
  packet.header.qd_count = 1;

  DnsQuestion question{split(url, "."), SectionType::A, SectionClass::IN};
  packet.questions.push_back(question);

  return packet;
}
