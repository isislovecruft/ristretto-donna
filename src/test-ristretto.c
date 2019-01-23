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

  return (int)result;
}

int main(int argc, char **argv)
{
  int result;

  result = test_ristretto_decode_basepoint();

  return 0;
}
