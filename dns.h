#pragma once

#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>

#include "helper.h"

enum class SectionClass : uint16_t { IN = 1, CS = 2, CH = 3, HS = 4, ANY = 255 };
enum class SectionType : uint16_t {
  A = 1,      // a host address
  NS = 2,     // an authoritative name server
  MD = 3,     // a mail destination (Obsolete - use MX)
  MF = 4,     // a mail forwarder (Obsolete - use MX)
  CNAME = 5,  // the canonical name for an alias
  SOA = 6,    // marks the start of a zone of authority
  MB = 7,     // a mailbox domain name (EXPERIMENTAL)
  MG = 8,     // a mail group member (EXPERIMENTAL)
  MR = 9,     // a mail rename domain name (EXPERIMENTAL)
  _NULL = 10, // a null RR (EXPERIMENTAL)
  WKS = 11,   // a well known service description
  PTR = 12,   // a domain name pointer
  HINFO = 13, // host information
  MINFO = 14, // mailbox or mail list information
  MX = 15,    // mail exchange
  TXT = 16,   // text strings
};

struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
};

struct DnsQuestion {
  std::vector<std::string> lables;
  SectionType type;
  SectionClass qclass;
};

struct DnsSection {
  std::vector<std::string> lables;
  SectionType type;
  SectionClass sclass;
  uint32_t ttl; // cache interval
  uint16_t rd_length;
  std::vector<uint8_t> rdata;
};

/* template <typename T> T reverse_bytes(const uint8_t *bytes); */
void push_chars(std::vector<uint8_t> &bytes, const char *chars, const int len);
template <class T> void rpush_bytes(std::vector<uint8_t> &bytes, const T &obj);

// Only supports basic querries
class DnsPacketTcp {
  // The length field is only used for tcp connections and does not count towards offsets
  uint16_t length;
  DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<DnsSection> answers;
  std::vector<DnsSection> authorities;
  std::vector<DnsSection> additionals;

  DnsPacketTcp() : length{0}, header{}, questions{}, answers{}, authorities{}, additionals{} {
  }

  inline static bool is_name_pointer(const uint8_t val);
  static void parse_name(std::vector<std::string> &name, const uint8_t **cur, const uint8_t *data);
  static DnsSection parse_section(const uint8_t **cur, const uint8_t *data);
  static DnsQuestion parse_question(const uint8_t **cur, const uint8_t *data);

public:
  static DnsPacketTcp url_querry_packet(const uint16_t id, const std::string &url);

  static DnsPacketTcp deserialize(const uint8_t *data);
  std::vector<uint8_t> serialize() const;
  std::string to_string() const;
};

