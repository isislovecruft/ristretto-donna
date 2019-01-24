// This file is part of ristretto-donna.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#include <stdint.h>
#include <stdio.h>

#include "ristretto-donna.h"

int test_ristretto_decode_basepoint()
{
  ristretto_point_t point;
  uint8_t result;

  result = ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);

  if (result != 1) {
    printf("could not decode basepoint\n");
  }

  return (int)result;
}

int test_ristretto_encode_basepoint()
{
  ristretto_point_t point;
  unsigned char bytes[32];
  uint8_t result = 1;

  ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_encode(bytes, &point);

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

  result  = test_ristretto_decode_basepoint();
  result &= test_ristretto_encode_basepoint();
  result &= test_ristretto_ct_eq();

  return result;
}
