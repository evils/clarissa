#pragma once

#include <stdint.h>

#include <libtq/macros.h>

#define TQ_DEF_PUT_BE(sign, bits)					\
  static inline void TQ_PASTE4(tq_serialization_put_, sign, bits, _be) (uint8_t *buffer, TQ_PASTE3(sign, bits, _t) value) { \
    for (int i = 0; i < (bits / 8); i++) {				\
      buffer[i] = (uint8_t)(value >> (bits - 8*(i+1)));			\
    }									\
  }

#define TQ_DEF_PUT_LE(sign, bits)					\
  static inline void TQ_PASTE4(tq_serialization_put_, sign, bits, _le) (uint8_t *buffer, TQ_PASTE3(sign, bits, _t) value) { \
    for (int i = 0; i < (bits / 8); i++) {				\
      buffer[i] = (uint8_t)(value >> (8*i));				\
    }									\
  }


#define TQ_DEF_PUT(bits)			\
  TQ_DEF_PUT_BE(int, bits)			\
    TQ_DEF_PUT_BE(uint, bits)			\
    TQ_DEF_PUT_LE(int, bits)			\
    TQ_DEF_PUT_LE(uint, bits)

TQ_DEF_PUT(64)
TQ_DEF_PUT(32)
TQ_DEF_PUT(16)

static inline void tq_serialization_put_u8_be(uint8_t *buffer, uint16_t value) {
  *buffer = value;
}

static inline void tq_serialization_put_u8_le(uint8_t *buffer, uint16_t value) {
  *buffer = value;
}

#define tq_serialization_put_u64_ne(buffer, value) tq_serialization_put_u64_be(buffer, value)
#define tq_serialization_put_u32_ne(buffer, value) tq_serialization_put_u32_be(buffer, value)
#define tq_serialization_put_u16_ne(buffer, value) tq_serialization_put_u16_be(buffer, value)
#define tq_serialization_put_u8_ne(buffer, value) tq_serialization_put_u8_be(buffer, value)

#undef TQ_DEF_PUT_BE
#undef TQ_DEF_PUT_LE
#undef TQ_DEF_PUT


// Getters
#define TQ_DEF_GET_BE(sign, bits)					\
  static inline TQ_PASTE3(sign, bits, _t) TQ_PASTE4(tq_serialization_get_, sign, bits, _be) (uint8_t *buffer) { \
    typedef TQ_PASTE3(sign, bits, _t) result_t;				\
    result_t result = 0;						\
    for (int i = 0; i < (bits / 8); i++) {				\
      result |= (result_t)(buffer[i]) << (bits - 8*(i+1));		\
    }									\
    return result;							\
  }

#define TQ_DEF_GET_LE(sign, bits)					\
  static inline TQ_PASTE3(sign, bits, _t) TQ_PASTE4(tq_serialization_get_, sign, bits, _le) (uint8_t *buffer) { \
    typedef TQ_PASTE3(sign, bits, _t) result_t;				\
    result_t result = 0;						\
    for (int i = 0; i < (bits / 8); i++) {				\
      result |= (result_t)(buffer[i]) << (8*i);				\
    }									\
    return result;							\
  }


#define TQ_DEF_GET(bits)			\
  TQ_DEF_GET_BE(int, bits)			\
    TQ_DEF_GET_BE(uint, bits)			\
    TQ_DEF_GET_LE(int, bits)			\
    TQ_DEF_GET_LE(uint, bits)

TQ_DEF_GET(64)
TQ_DEF_GET(32)
TQ_DEF_GET(16)

#undef TQ_DEF_GET_BE
#undef TQ_DEF_GET_LE
#undef TQ_DEF_GET

