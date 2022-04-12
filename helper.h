#pragma once

#include <stdint.h>
#include <vector>

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

