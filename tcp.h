#pragma once

#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <sys/socket.h>
#include <vector>

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
  TcpStream(const char *addr, uint16_t port);
  void ssend(const uint8_t *msg, const int len);
  std::vector<uint8_t> rrecv();
  ~TcpStream();
};
