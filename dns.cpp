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

std::string DnsPacket::to_string() const {
  auto str = std::string();

  str.append("DnsPacket{id: ");
  str.append(std::to_string(this->header.ID));

  str.append(", qdcount: ");
  str.append(std::to_string(this->header.qd_count));

  str.append(", ancount: ");
  str.append(std::to_string(this->header.an_count));

  str.append(", questions:");
  for (const auto &ques : this->questions) {
    str.append(" ");
    str.append(ques.name);
  }

  str.append(", answers:");
  for (const auto &ans : this->answers) {
    str.append(" ");
    str.append(std::to_string(ans.sclass));
    str.append(".");
    str.append(std::to_string(ans.type));
    str.append(".");
    str.append(ans.name);
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

DnsPacket DnsPacket::deserialize(const uint8_t *data) {
  auto packet = DnsPacket{};
  auto cursor = data;

  // On tcp connection first two bytes are a length
  packet.length = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  data += 2;

  packet.header.ID = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.flags = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.qd_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.an_count = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.NSCOUNT = reverse_bytes<uint16_t>(cursor);
  cursor += 2;
  packet.header.ARCOUNT = reverse_bytes<uint16_t>(cursor);
  cursor += 2;

  // Parse question section
  for (int i = 0; i < packet.header.qd_count; i++) {
    auto question = DnsPacket::parse_question(&cursor, data);
    packet.questions.push_back(question);
  }

  // Parse answer section
  for (int i = 0; i < packet.header.an_count; i++) {
    auto answer = DnsPacket::parse_section(&cursor, data);
    if (answer.type != SectionType::A || answer.sclass != SectionClass::IN) {
      // Not implemented
      throw std::exception();
    }
    packet.answers.push_back(answer);
  }

  // Parse authority section
  for (int i = 0; i < packet.header.NSCOUNT; i++) {
    auto authority = DnsPacket::parse_section(&cursor, data);
    packet.authorities.push_back(authority);
  }

  // Parse additional section
  for (int i = 0; i < packet.header.ARCOUNT; i++) {
    auto additional = DnsPacket::parse_section(&cursor, data);
    packet.additionals.push_back(additional);
  }

  return packet;
}

inline bool DnsPacket::is_name_pointer(const uint8_t val) {
  // It's a name pointer if first two bits are set
  return (val & 0xC0) == 0xC0;
}

void DnsPacket::parse_name(std::string &name, const uint8_t **cur, const uint8_t *data) {
  auto cursor = *cur;

  while (1) {
    // Dns compression points to previous def of same name
    if (DnsPacket::is_name_pointer(*cursor)) {
      auto offset = reverse_bytes<uint16_t>(cursor);
      // Unset most sig two bits that denote the pointer
      offset ^= 0xC000;

      cursor += 2;
      auto name_cursor = data + offset;
      // Jump to name pointer and continue reading name
      DnsPacket::parse_name(name, &name_cursor, data);
      break;
    } else {
      uint8_t char_nr = *(cursor++);
      name.append(cursor, cursor + char_nr);
      cursor += char_nr;
      if (*cursor != '\0') {
        name.append(".");
      } else {
        cursor++;
        break;
      }
    }
  }

  *cur = cursor;
}

DnsSection DnsPacket::parse_section(const uint8_t **cur, const uint8_t *data) {
  auto section = DnsSection{};
  auto cursor = *cur;

  DnsPacket::parse_name(section.name, &cursor, data);

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

DnsQuestion DnsPacket::parse_question(const uint8_t **cur, const uint8_t *data) {
  auto question = DnsQuestion{};
  auto cursor = *cur;

  DnsPacket::parse_name(question.name, &cursor, data);

  question.type = static_cast<SectionType>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;
  question.qclass = static_cast<SectionClass>(reverse_bytes<uint16_t>(cursor));
  cursor += 2;

  *cur = cursor;
  return question;
}
