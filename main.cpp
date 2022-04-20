#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <memory>

#include "dns.h"
#include "helper.h"
#include "tcp.h"

void querry_dns(std::string url) {

  auto packet = DnsPacketTcp::url_querry_packet(42, "google.ro");
  auto packet_bytes = packet.serialize();

  // Make request
  // TODO: get the dns url from os
  auto stream = TcpStream("193.231.252.1", 53);
  stream.ssend(static_cast<uint8_t *>(&packet_bytes[0]), packet_bytes.size());
  auto response = stream.rrecv();

  auto resp_packet = DnsPacketTcp::deserialize(&response[0]);
  std::cout << resp_packet.to_string() << std::endl;
}

int main() {
  querry_dns("google.com");
}
