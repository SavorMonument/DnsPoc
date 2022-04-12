#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>

#include "dns.h"
#include "tcp.h"
#include "helper.h"

void push_chars(std::vector<uint8_t> &bytes, const char *chars, const int len) {
  bytes.push_back(len);
  for (int i = 0; i < len; i++) {
    bytes.push_back(*(chars + i));
  }
}

std::vector<uint8_t> prepare_question(const std::string &url, const uint16_t port) {
  auto question = std::vector<uint8_t>();
  auto dns_header = DnsHeader{42, 0, 1, 0, 0, 0};
  // Make request recursive
  dns_header.flags |= 0x1 << 8;

  rpush_bytes(question, (uint16_t)28);

  rpush_bytes(question, dns_header.ID);
  rpush_bytes(question, dns_header.flags);
  rpush_bytes(question, dns_header.qd_count);
  rpush_bytes(question, dns_header.an_count);
  rpush_bytes(question, dns_header.NSCOUNT);
  rpush_bytes(question, dns_header.ARCOUNT);

  push_chars(question, "google", 6);
  push_chars(question, "com", 3);
  question.push_back(0);

  rpush_bytes(question, SectionType::A);
  rpush_bytes(question, SectionClass::IN);

  return question;
}

void querry_dns(std::string url, uint16_t port) {

  auto question = prepare_question(url, port);

  // Make request
  auto stream = TcpStream("193.231.252.1", 53);
  stream.ssend(reinterpret_cast<uint8_t *>(&question[0]), question.size());
  auto response = stream.rrecv();

  auto packet = DnsPacket::deserialize(&response[0]);
  std::cout << packet.to_string() << std::endl;
}

int main() {

  querry_dns("", 10);
  /* char bytes[] = {0, 0, 0, 1}; */

  /* printf("Bytes int: %d\n", *((int*) bytes)); */
  /* printf("Bytes: %d %d %d %d \n", bytes[0], bytes[1], bytes[2], bytes[3]); */
  /* uint32_t val = Network::from_big_endian<uint32_t>(bytes); */

  /* std::cout << "Out: " << val << "\n"; */
}
