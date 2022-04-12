#include "tcp.h"

TcpStream::TcpStream(const char *addr, uint16_t port) {
  this->sock_fd = socket(AF_INET, SOCK_STREAM, 0);

  // Socket address init
  struct sockaddr_in ipv4addr {
    AF_INET, htons(port), {
    }
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

void TcpStream::ssend(const uint8_t *msg, const int len) {
  int bytes_sent = send(this->sock_fd, msg, len, 0);
  if (-1 == bytes_sent || bytes_sent != len) {
    throw StreamError("Error on send");
  }
}

std::vector<uint8_t> TcpStream::rrecv() {
  int recv_count = recv(this->sock_fd, this->buf, 4096, 0);
  if (-1 == recv_count) {
    perror("Recv");
    throw StreamError("Error on recv");
  }

  return std::vector<uint8_t>(this->buf, this->buf + recv_count);
}

TcpStream::~TcpStream() {
  shutdown(this->sock_fd, 2);
  std::cout << "Disconnected\n";
}
