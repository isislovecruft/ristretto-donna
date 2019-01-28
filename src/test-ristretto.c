// This file is part of ristretto-donna.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#define RISTRETTO_DONNA_PRIVATE

#include <stdint.h>
#include <stdio.h>

#include "ristretto-donna.h"

/// Random element a of GF(2^255-19), from Sage
/// a = 10703145068883540813293858232352184442332212228051251926706380353716438957572
const uint8_t A_BYTES[32] = {
  0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
  0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
  0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
  0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17
};

/// Byte representation of a**2
const uint8_t ASQ_BYTES[32] = {
  0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab,
  0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d,
  0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2,
  0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62
};

/// Byte representation of 1/a
const uint8_t AINV_BYTES[32] = {
  0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a,
  0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70,
  0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b,
  0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30
};

/// Byte representation of a^((p-5)/8)
const uint8_t AP58_BYTES[32] = {
  0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36,
  0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1, 0x59,
  0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f,
  0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61, 0x21, 0x55
};

int test_curve25519_expand_random_field_element()
{
  bignum25519 a;

  curve25519_expand(a, A_BYTES);

  printf("a=");
  fe_print(a);

  return 1;
}

int test_invsqrt_random_field_element()
{
  bignum25519 check, v, v_invsqrt;
  uint8_t result;

  // Use v = decode(ASQ_BYTES) so it's guaranteed to be square

  //curve25519_expand(v, ASQ_BYTES);
  curve25519_copy(v, one);
  result = curve25519_invsqrt(v_invsqrt, v);

  PRINT(("invsqrt test: "));
  if (result == 1) {
    // expect v_invsqrt = sqrt(1/v)
    // check = 1/v
    curve25519_square(check, v_invsqrt);
    // check = 1
    curve25519_mul(check, check, v);
    // assert check == 1
    if (bignum25519_ct_eq(check, one) == 1) {
      PRINT(("OKAY invsqrt computed correctly with tweak=1"));
      return 1;
    } else {
      PRINT(("FAIL invsqrt not computed correctly with tweak=1"));
      return 0;
    }
  } else if (result == 0) {
    // expect v_invsqrt = sqrt(i/v)
    // check = i/v
    curve25519_square(check, v_invsqrt);
    // check = i
    curve25519_mul(check, check, v);
    // assert check == i
    if (bignum25519_ct_eq(check, SQRT_M1) == 1) {
      PRINT(("OKAY invsqrt computed correctly with tweak=i"));
      return 1;
    } else {
      PRINT(("FAIL invsqrt not computed correctly with tweak=i"));
      return 0;
    }
  } else {
    PRINT(("FAIL invsqrt did not return 0 or 1"));
    return 0;
  }

}

int test_ristretto_decode_random_point()
{
  ristretto_point_t point;
  uint8_t result;

  result = ristretto_decode(&point, A_BYTES);

  printf("decoding random point: ");
  if (result != 1) {
    printf("FAIL result=%d\n", result);
  } else {
    printf("OKAY");
  }

  return (int)result;
}

int test_ristretto_decode_basepoint()
{
  ristretto_point_t point;
  uint8_t result;

  result = ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);

  printf("decoding basepoint: ");
  if (result != 1) {
    printf("FAIL result=%d\n", result);
  } else {
    printf("OKAY");
  }

  return (int)result;
}

int test_ristretto_encode_basepoint()
{
  ristretto_point_t *point;
  unsigned char bytes[32];
  uint8_t result = 1;


  ristretto_decode(point, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_encode(bytes, point);

  for (unsigned char i=0; i<32; i++) {
    if (bytes[i] != RISTRETTO_BASEPOINT_COMPRESSED[i]) {
      printf("byte %d did not match: original=%u encoded=%u\n",
             i, RISTRETTO_BASEPOINT_COMPRESSED[i], bytes[i]);
      result = 0;
    }
  }

  return (int)result;
}

int test_ristretto_ct_eq()
{
  ristretto_point_t *a, *b;
  int result;

  ristretto_decode(a, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_decode(b, RISTRETTO_BASEPOINT_COMPRESSED);

  result = ristretto_ct_eq(a, b);

  return result;
}

int main(int argc, char **argv)
{
  int result;

  result  = test_invsqrt_random_field_element();
  result &= test_ristretto_decode_random_point();
  result &= test_ristretto_decode_basepoint();
  result &= test_ristretto_encode_basepoint();
  result &= test_ristretto_ct_eq();
  result &= test_curve25519_expand_random_field_element();

  return result;
}
