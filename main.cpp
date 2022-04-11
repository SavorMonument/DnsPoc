#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <sys/socket.h>
#include <vector>

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

class StreamError : public std::exception {
  const char *str;

  const char *what() const noexcept override {
    return this->str;
  }

public:
  StreamError(const char *str) {
    this->str = str;
  }
};

class TcpStream {
  static const int BUF_SIZE = 4096;
  char buf[BUF_SIZE];

  int sock_fd;

public:
  TcpStream(const char *addr, uint16_t port) {
    this->sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Socket address init
    struct sockaddr_in ipv4addr {
      AF_INET, htons(port), 0
    };
    inet_pton(AF_INET, addr, &(ipv4addr.sin_addr));

    // Socket timeout
    struct timeval time_val {
      3, 100
    };
    setsockopt(this->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &time_val, sizeof(time_val));

    // Connect
    if (-1 == connect(this->sock_fd, reinterpret_cast<sockaddr *>(&ipv4addr), sizeof(ipv4addr))) {
      perror("Connect");
      throw StreamError("Error on connect");
    }
    std::cout << "Connected\n";
  }

  void ssend(const uint8_t *msg, const int len) {
    int bytes_sent = send(this->sock_fd, msg, len, 0);
    if (-1 == bytes_sent || bytes_sent != len) {
      throw StreamError("Error on send");
    }
  }

  std::vector<uint8_t> rrecv() {
    int recv_count = recv(this->sock_fd, this->buf, 4096, 0);
    if (-1 == recv_count) {
      perror("Recv");
      throw StreamError("Error on recv");
    }

    return std::vector<uint8_t>(this->buf, this->buf + recv_count);
  }

  ~TcpStream() {
    shutdown(this->sock_fd, 2);
    std::cout << "Disconnected\n";
  }
};

namespace Network {

struct DnsHeader {
  uint16_t ID;
  uint16_t flags;
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
};

constexpr uint32_t HEADER_BYTES = 12;

template <typename T> T reverse_bytes(const uint8_t *bytes) {
  int size = sizeof(T);
  T val = {};
  uint8_t *val_p = (uint8_t *)&val;

  for (int i = size - 1; i >= 0; i--) {
    *(val_p + (size - (i + 1))) = *(bytes + i);
  }

  return val;
}

template <class T> void rpush_bytes(std::vector<uint8_t> &bytes, const T &obj) {
  const uint8_t *obj_bytes = reinterpret_cast<const uint8_t *>(&obj);
  for (int i = sizeof(obj) - 1; i >= 0; i--) {
    bytes.push_back(*(obj_bytes + i));
  }
}

template <class T> void insert_bytes(std::vector<uint8_t> &bytes, const T &obj) {
  const uint8_t *obj_bytes = reinterpret_cast<const uint8_t *>(&obj);
  for (int i = 0; i < sizeof(obj); i++) {
    bytes.push_back(*(obj_bytes + i));
  }
}

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
  dns_header.flags |= 0x1 << 6;

  rpush_bytes(question, (uint16_t)28);

  rpush_bytes(question, dns_header.ID);
  rpush_bytes(question, dns_header.flags);
  rpush_bytes(question, dns_header.QDCOUNT);
  rpush_bytes(question, dns_header.ANCOUNT);
  rpush_bytes(question, dns_header.NSCOUNT);
  rpush_bytes(question, dns_header.ARCOUNT);

  push_chars(question, "google", 6);
  push_chars(question, "com", 3);
  question.push_back(0);

  rpush_bytes(question, SectionType::A);
  rpush_bytes(question, SectionClass::IN);

  return question;
}

}; // namespace Network

struct DnsQuestion {
  std::string qname;
  SectionType qtype;
  SectionClass qclass;
};

struct DnsSection {};

class DnsPacket {

  void serialize(std::vector<uint8_t> &data) const {
    /* Dns::rpush_bytes(data, this->ID); */
    /* Dns::rpush_bytes(data, dns_header.flags); */
    /* Dns::rpush_bytes(data, dns_header.QDCOUNT); */
    /* Dns::rpush_bytes(data, dns_header.ANCOUNT); */
    /* Dns::rpush_bytes(data, dns_header.NSCOUNT); */
    /* Dns::rpush_bytes(data, dns_header.ARCOUNT); */
  }

  void deserialize(const uint8_t *data) const {
  }

  /* static DnsQuestion parse_section(const uint8_t **cur) { */
  /*   auto section = DnsSection{}; */
  /*   auto cursor = *cur; */


  /* } */

  static DnsQuestion parse_question(const uint8_t **cur) {
    auto question = DnsQuestion{};
    auto cursor = *cur;

    while (*cursor != '\0') {
      uint8_t char_nr = *(cursor++);
      question.qname.append(cursor, cursor + char_nr);
      question.qname.append(".");
      cursor += char_nr;
    }
    question.qname.pop_back();

    question.qtype = static_cast<SectionType>(Network::reverse_bytes<uint16_t>(cursor));
    cursor += 2;
    question.qclass = static_cast<SectionClass>(Network::reverse_bytes<uint16_t>(cursor));
    cursor += 2;

    return question;
  }

  Network::DnsHeader header;
  std::vector<DnsQuestion> questions;
  std::vector<std::string> answers;
  std::vector<std::string> authorities;
  std::vector<std::string> additionals;

  DnsPacket() {
  }

public:
  /* std::ostream &operator<<(std::ostream &os) { */
  /*   os << "DnsPacket{id: " << this->header.ID; */
  /*   for (auto qus : this->question) { */
  /*     os << "Question: " << std::to_string(qus.qtype) << qus.qclass << qus.qname << std::endl; */
  /*   } */
  /*   os << "}" << std::endl; */

  /*   return os; */
  /* } */

  std::string to_string() {
    auto str = std::string();

    str.append("DnsPacket{id: ");
    str.append(std::to_string(this->header.ID));
    str.append(", questions:");

    for (auto ques: this->questions) {
      str.append(" ");
      str.append(ques.qname);
    }

    str.append("}");
    return str;
  }

  static DnsPacket from_net_bytes(const uint8_t *data) {
    auto packet = DnsPacket{};
    auto cursor = data;

    packet.header.ID = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.flags = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.flags = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.QDCOUNT = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.ANCOUNT = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.NSCOUNT = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;
    packet.header.ARCOUNT = Network::reverse_bytes<uint16_t>(cursor);
    cursor += 2;

    // Parse question section
    for (int i = 0; i < packet.header.QDCOUNT; i++) {
      auto question = DnsPacket::parse_question(&cursor);
      packet.questions.push_back(question);
    }

    /* // Parse answer section */
    /* for (int i = 0; i < packet.header.ANCOUNT; i++) { */
    /*   auto answer = DnsPacket::parse_section(cursor); */
    /*   cursor += answer.length(); */
    /*   packet.answers.push_back(answer); */
    /* } */

    /* // Parse authority section */
    /* for (int i = 0; i < packet.header.NSCOUNT; i++) { */
    /*   auto authority = DnsPacket::parse_section(cursor); */
    /*   cursor += authority.length(); */
    /*   packet.authorities.push_back(authority); */
    /* } */

    /* // Parse additional section */
    /* for (int i = 0; i < packet.header.ARCOUNT; i++) { */
    /*   auto additional = DnsPacket::parse_section(cursor); */
    /*   cursor += additional.length(); */
    /*   packet.additionals.push_back(additional); */
    /* } */

    return packet;
  }
};

void querry_dns(std::string url, uint16_t port) {

  auto question = Network::prepare_question(url, port);

  // Make request
  auto stream = TcpStream("193.231.252.1", 53);
  stream.ssend(reinterpret_cast<uint8_t *>(&question[0]), question.size());
  auto response = stream.rrecv();

  auto packet = DnsPacket::from_net_bytes(&response[0]);
  std::cout << packet.to_string() << std::endl; 

  /* auto answer_start = &response[Network::HEADER_BYTES]; */

  /* for (char c : response) { */
  /*   if (c > 41 && c < 123) { */
  /*     std::cout << c; */
  /*   } else { */
  /*     std::cout << (int)c; */
  /*   } */
  /* } */
  /* std::cout << "\n"; */
}

int main() {

  querry_dns("", 10);
  /* char bytes[] = {0, 0, 0, 1}; */

  /* printf("Bytes int: %d\n", *((int*) bytes)); */
  /* printf("Bytes: %d %d %d %d \n", bytes[0], bytes[1], bytes[2], bytes[3]); */
  /* uint32_t val = Network::from_big_endian<uint32_t>(bytes); */

  /* std::cout << "Out: " << val << "\n"; */
}
