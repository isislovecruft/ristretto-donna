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

const unsigned char IDENTITY[32] = {0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0};

void print_uchar32(unsigned char uchar[32])
{
  unsigned char i;

  for (i=0; i<32; i++) {
#ifdef DEBUGGING
    printf("%02x, ", uchar[i]);
#endif
  }
#ifdef DEBUGGING
  printf("\n");
#endif
}

int test_curve25519_expand_random_field_element()
{
  bignum25519 a;
  unsigned char a_bytes[32]; // discard the const qualifier
  unsigned char b[32];

  printf("expanding and contracting random field element: ");

  memcpy(a_bytes, A_BYTES, 32);

  curve25519_expand(a, a_bytes);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(A_BYTES, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32(a_bytes);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_curve25519_expand_basepoint()
{
  bignum25519 a;
  unsigned char b[32];

  printf("expanding and contracting basepoint: ");

  curve25519_expand(a, RISTRETTO_BASEPOINT_COMPRESSED);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(RISTRETTO_BASEPOINT_COMPRESSED, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32(RISTRETTO_BASEPOINT_COMPRESSED);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_curve25519_expand_identity()
{
  bignum25519 a;
  unsigned char b[32];

  printf("test expanding and contracting additive identity: ");

  curve25519_expand(a, IDENTITY);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(IDENTITY, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32((unsigned char*)IDENTITY);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_ge25519_unpack_pack()
{
  ge25519 a;
  unsigned char b[32];
  int result;

  printf("test unpacking and packing a group element: ");

  result = ge25519_unpack_negative_vartime(&a, IDENTITY);
  ge25519_pack_without_parity(b, &a);

  if (!uint8_32_ct_eq(b, IDENTITY)) {
    result &= 0;
  }

  if (result != 1) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32((unsigned char*)IDENTITY);
    PRINT("b="); print_uchar32(b);
  } else {
    printf("OKAY\n");
  }

  return result;
}

int test_invsqrt_random_field_element()
{
  bignum25519 check, v, v_invsqrt;
  uint8_t result;

  // Use v = decode(ASQ_BYTES) so it's guaranteed to be square

  //curve25519_expand(v, ASQ_BYTES);
  curve25519_copy(v, one);
  result = curve25519_invsqrt(v_invsqrt, v);

  printf("invsqrt test: ");
  if (result == 1) {
    // expect v_invsqrt = sqrt(1/v)
    // check = 1/v
    curve25519_square(check, v_invsqrt);
    // check = 1
    curve25519_mul(check, check, v);
    // assert check == 1
    if (bignum25519_ct_eq(check, one) == 1) {
      printf("OKAY invsqrt computed correctly with tweak=1\n");
      return 1;
    } else {
      printf("FAIL invsqrt not computed correctly with tweak=1\n");
      PRINT("v_invsqrt = "); fe_print(v_invsqrt);
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
      printf("OKAY invsqrt computed correctly with tweak=i\n");
      return 1;
    } else {
      printf("FAIL invsqrt not computed correctly with tweak=i\n");
      return 0;
    }
  } else {
    printf("FAIL invsqrt did not return 0 or 1\n");
    return 0;
  }

}

int test_ristretto_decode_random_invalid_point()
{
  ristretto_point_t point;
  uint8_t result;

  // This field element doesn't represent a valid point…
  result = ristretto_decode(&point, A_BYTES);

  printf("decoding random invalid point: ");
  if (result != 0) { // …and thus we want the decoding to fail.
    printf("FAIL result=%d\n", result);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
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
    printf("OKAY\n");
  }

  return (int)result;
}

int test_ristretto_encode_small_multiples_of_basepoint()
{
  uint8_t result = 1;
  ristretto_point_t P, B;
  unsigned char i;
  unsigned char encoded[32];
  unsigned char encodings_of_small_multiples[16][32] = {
    // This is the identity
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    // This is the basepoint
    {0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
     0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76},
    // These are small multiples of the basepoint
    {0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c, 0xea, 0x23,
     0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c, 0x73, 0xa3, 0xb9, 0x19},
    {0x94, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e, 0xce, 0x4f, 0x23, 0xf0, 0x44, 0xee, 0x27, 0xd5,
     0xd1, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62, 0x16, 0x6b, 0x16, 0x15, 0x2a, 0x9d, 0x02, 0x59},
    {0xda, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46, 0x6f, 0xfa, 0xdf, 0xe0, 0xb3, 0x29, 0x3a, 0xb3,
     0xd9, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53, 0x58, 0xf5, 0x68, 0x32, 0x2d, 0xaf, 0x6a, 0x57},
    {0xe8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1, 0xd3, 0x33, 0x70, 0x80, 0x18, 0x7c, 0xf7, 0x68,
     0x42, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49, 0x5a, 0xb8, 0x12, 0xc4, 0x16, 0x0f, 0xf4, 0x4e},
    {0xf6, 0x47, 0x46, 0xd3, 0xc9, 0x2b, 0x13, 0x05, 0x0e, 0xd8, 0xd8, 0x02, 0x36, 0xa7, 0xf0, 0x00,
     0x7c, 0x3b, 0x3f, 0x96, 0x2f, 0x5b, 0xa7, 0x93, 0xd1, 0x9a, 0x60, 0x1e, 0xbb, 0x1d, 0xf4, 0x03},
    {0x44, 0xf5, 0x35, 0x20, 0x92, 0x6e, 0xc8, 0x1f, 0xbd, 0x5a, 0x38, 0x78, 0x45, 0xbe, 0xb7, 0xdf,
     0x85, 0xa9, 0x6a, 0x24, 0xec, 0xe1, 0x87, 0x38, 0xbd, 0xcf, 0xa6, 0xa7, 0x82, 0x2a, 0x17, 0x6d},
    {0x90, 0x32, 0x93, 0xd8, 0xf2, 0x28, 0x7e, 0xbe, 0x10, 0xe2, 0x37, 0x4d, 0xc1, 0xa5, 0x3e, 0x0b,
     0xc8, 0x87, 0xe5, 0x92, 0x69, 0x9f, 0x02, 0xd0, 0x77, 0xd5, 0x26, 0x3c, 0xdd, 0x55, 0x60, 0x1c},
    {0x02, 0x62, 0x2a, 0xce, 0x8f, 0x73, 0x03, 0xa3, 0x1c, 0xaf, 0xc6, 0x3f, 0x8f, 0xc4, 0x8f, 0xdc,
     0x16, 0xe1, 0xc8, 0xc8, 0xd2, 0x34, 0xb2, 0xf0, 0xd6, 0x68, 0x52, 0x82, 0xa9, 0x07, 0x60, 0x31},
    {0x20, 0x70, 0x6f, 0xd7, 0x88, 0xb2, 0x72, 0x0a, 0x1e, 0xd2, 0xa5, 0xda, 0xd4, 0x95, 0x2b, 0x01,
     0xf4, 0x13, 0xbc, 0xf0, 0xe7, 0x56, 0x4d, 0xe8, 0xcd, 0xc8, 0x16, 0x68, 0x9e, 0x2d, 0xb9, 0x5f},
    {0xbc, 0xe8, 0x3f, 0x8b, 0xa5, 0xdd, 0x2f, 0xa5, 0x72, 0x86, 0x4c, 0x24, 0xba, 0x18, 0x10, 0xf9,
     0x52, 0x2b, 0xc6, 0x00, 0x4a, 0xfe, 0x95, 0x87, 0x7a, 0xc7, 0x32, 0x41, 0xca, 0xfd, 0xab, 0x42},
    {0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad, 0xaf, 0xca,
     0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca, 0x8f, 0xf8, 0x44, 0x60},
    {0xaa, 0x52, 0xe0, 0x00, 0xdf, 0x2e, 0x16, 0xf5, 0x5f, 0xb1, 0x03, 0x2f, 0xc3, 0x3b, 0xc4, 0x27,
     0x42, 0xda, 0xd6, 0xbd, 0x5a, 0x8f, 0xc0, 0xbe, 0x01, 0x67, 0x43, 0x6c, 0x59, 0x48, 0x50, 0x1f},
    {0x46, 0x37, 0x6b, 0x80, 0xf4, 0x09, 0xb2, 0x9d, 0xc2, 0xb5, 0xf6, 0xf0, 0xc5, 0x25, 0x91, 0x99,
     0x08, 0x96, 0xe5, 0x71, 0x6f, 0x41, 0x47, 0x7c, 0xd3, 0x00, 0x85, 0xab, 0x7f, 0x10, 0x30, 0x1e},
    {0xe0, 0xc4, 0x18, 0xf7, 0xc8, 0xd9, 0xc4, 0xcd, 0xd7, 0x39, 0x5b, 0x93, 0xea, 0x12, 0x4f, 0x3a,
     0xd9, 0x90, 0x21, 0xbb, 0x68, 0x1d, 0xfc, 0x33, 0x02, 0xa9, 0xd9, 0x9a, 0x2e, 0x53, 0xe6, 0x4e},
  };

  printf("encoding small multiples of basepoint: ");

  ristretto_decode(&P, IDENTITY);
  ristretto_decode(&B, RISTRETTO_BASEPOINT_COMPRESSED);

  for (i=0; i<16; i++) {
    ristretto_encode(encoded, (const ristretto_point_t*)&P);

    if (!uint8_32_ct_eq(encoded, encodings_of_small_multiples[i])) {
      printf("  - FAIL small multiple #%d failed to encode correctly\n", i);
      PRINT("    original = ");
      print_uchar32(encodings_of_small_multiples[i]);
      PRINT("    encoded = ");
      print_uchar32(encoded);
      result &= 0;
    }

    ge25519_add(&P.point, &P.point, (const ge25519*)&B.point); // add another multiple of the basepoint
  }

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_ristretto_encode_identity()
{
  ristretto_point_t point;
  unsigned char bytes[32];
  unsigned char i;
  uint8_t result = 1;

  printf("test ristretto encode identity: ");

  ristretto_decode(&point, IDENTITY);
  ristretto_encode(bytes, &point);

  for (i=0; i<32; i++) {
    if (bytes[i] != IDENTITY[i]) {
      PRINT("byte %d did not match: original=%u encoded=%u",
            i, IDENTITY[i], bytes[i]);
      result = 0;
    }
  }

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_ristretto_encode_basepoint()
{
  ristretto_point_t point;
  unsigned char bytes[32];
  unsigned char i;
  uint8_t result = 1;

  printf("test ristretto encode basepoint: ");

  ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_encode(bytes, &point);

  for (i=0; i<32; i++) {
    if (bytes[i] != RISTRETTO_BASEPOINT_COMPRESSED[i]) {
      PRINT("byte %d did not match: original=%u encoded=%u",
            i, RISTRETTO_BASEPOINT_COMPRESSED[i], bytes[i]);
      result = 0;
    }
  }

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_uint8_32_ct_eq()
{
  uint8_t zero[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, };
  uint8_t one[32] = { 1, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, };
  int ret = 1;

  printf("test 32 byte array equality (0==0): ");
  if (uint8_32_ct_eq(zero, zero) != 1) {
    printf("FAIL\n");
    ret = 0;
  } else {
    printf("OKAY\n");
  }

  printf("test 32 byte array equality (0==1): ");
  if (uint8_32_ct_eq(zero, one) != 0) {
    printf("FAIL\n");
    ret = 0;
  } else {
    printf("OKAY\n");
  }

  return ret;
}

int test_ristretto_ct_eq()
{
  ristretto_point_t a, b;
  int result;

  printf("test ristretto constant time equality check: ");

  ristretto_decode(&a, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_decode(&b, RISTRETTO_BASEPOINT_COMPRESSED);

  result = ristretto_ct_eq(&a, &b);

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return result;
}

int test_ristretto_flavor_elligator_versus_sage()
{
  // Test vectors extracted from ristretto.sage.
  //
  // Notice that all of the byte sequences have bit 255 set to 0; this is because
  // ristretto.sage does not mask the high bit of a field element.  When the high bit is set,
  // the ristretto.sage elligator implementation gives different results, since it takes a
  // different field element as input.
  unsigned char elements[16][32] = {
    {184, 249, 135, 49, 253, 123, 89, 113, 67, 160, 6, 239, 7, 105, 211, 41, 192, 249, 185, 57, 9, 102, 70, 198, 15, 127, 7, 26, 160, 102, 134, 71},
    {229, 14, 241, 227, 75, 9, 118, 60, 128, 153, 226, 21, 183, 217, 91, 136, 98, 0, 231, 156, 124, 77, 82, 139, 142, 134, 164, 169, 169, 62, 250, 52},
    {115, 109, 36, 220, 180, 223, 99, 6, 204, 169, 19, 29, 169, 68, 84, 23, 21, 109, 189, 149, 127, 205, 91, 102, 172, 35, 112, 35, 134, 69, 186, 34},
    {16, 49, 96, 107, 171, 199, 164, 9, 129, 16, 64, 62, 241, 63, 132, 173, 209, 160, 112, 215, 105, 50, 157, 81, 253, 105, 1, 154, 229, 25, 120, 83},
    {156, 131, 161, 162, 236, 251, 5, 187, 167, 171, 17, 178, 148, 210, 90, 207, 86, 21, 79, 161, 167, 215, 234, 1, 136, 242, 182, 248, 38, 85, 79, 86},
    {251, 177, 124, 54, 18, 101, 75, 235, 245, 186, 19, 46, 133, 157, 229, 64, 10, 136, 181, 185, 78, 144, 254, 167, 137, 49, 107, 10, 61, 10, 21, 25},
    {232, 193, 20, 68, 240, 77, 186, 77, 183, 40, 44, 86, 150, 31, 198, 212, 76, 81, 3, 217, 197, 8, 126, 128, 126, 152, 164, 208, 153, 44, 189, 77},
    {173, 229, 149, 177, 37, 230, 30, 69, 61, 56, 172, 190, 219, 115, 167, 194, 71, 134, 59, 75, 28, 244, 118, 26, 162, 97, 64, 16, 15, 189, 30, 64},
    {106, 71, 61, 107, 250, 117, 42, 151, 91, 202, 212, 100, 52, 188, 190, 21, 125, 218, 31, 18, 253, 241, 160, 133, 57, 242, 3, 164, 189, 68, 111, 75},
    {112, 204, 182, 90, 220, 198, 120, 73, 173, 107, 193, 17, 227, 40, 162, 36, 150, 141, 235, 55, 172, 183, 12, 39, 194, 136, 43, 153, 244, 118, 91, 89},
    {111, 24, 203, 123, 254, 189, 11, 162, 51, 196, 163, 136, 204, 143, 10, 222, 33, 112, 81, 205, 34, 35, 8, 66, 90, 6, 164, 58, 170, 177, 34, 25},
    {225, 183, 30, 52, 236, 82, 6, 183, 109, 25, 227, 181, 25, 82, 41, 193, 80, 77, 161, 80, 242, 203, 79, 204, 136, 245, 131, 110, 237, 106, 3, 58},
    {207, 246, 38, 56, 30, 86, 176, 90, 27, 200, 61, 42, 221, 27, 56, 210, 79, 178, 189, 120, 68, 193, 120, 167, 77, 185, 53, 197, 124, 128, 191, 126},
    {1, 136, 215, 80, 240, 46, 63, 147, 16, 244, 230, 207, 82, 189, 74, 50, 106, 169, 138, 86, 30, 131, 214, 202, 166, 125, 251, 228, 98, 24, 36, 21},
    {210, 207, 228, 56, 155, 116, 207, 54, 84, 195, 251, 215, 249, 199, 116, 75, 109, 239, 196, 251, 194, 246, 252, 228, 70, 146, 156, 35, 25, 39, 241, 4},
    {34, 116, 123, 9, 8, 40, 93, 189, 9, 103, 57, 103, 66, 227, 3, 2, 157, 107, 134, 219, 202, 74, 230, 154, 78, 107, 219, 195, 214, 14, 84, 80},
  };
  unsigned char encoded[32];
  // These are the images produced by applying our Elligator2 encoding to the above field element byte sequences.
  unsigned char encoded_images[16][32] = {
    {176, 157, 237, 97, 66, 29, 140, 166, 168, 94, 26, 157, 212, 216, 229, 160, 195, 246, 232, 239, 169, 112, 63, 193, 64, 32, 152, 69, 11, 190, 246, 86},
    {234, 141, 77, 203, 181, 225, 250, 74, 171, 62, 15, 118, 78, 212, 150, 19, 131, 14, 188, 238, 194, 244, 141, 138, 166, 162, 83, 122, 228, 201, 19, 26},
    {232, 231, 51, 92, 5, 168, 80, 36, 173, 179, 104, 68, 186, 149, 68, 40, 140, 170, 27, 103, 99, 140, 21, 242, 43, 62, 250, 134, 208, 255, 61, 89},
    {208, 120, 140, 129, 177, 179, 237, 159, 252, 160, 28, 13, 206, 5, 211, 241, 192, 218, 1, 97, 130, 241, 20, 169, 119, 46, 246, 29, 79, 80, 77, 84},
    {202, 11, 236, 145, 58, 12, 181, 157, 209, 6, 213, 88, 75, 147, 11, 119, 191, 139, 47, 142, 33, 36, 153, 193, 223, 183, 178, 8, 205, 120, 248, 110},
    {26, 66, 231, 67, 203, 175, 116, 130, 32, 136, 62, 253, 215, 46, 5, 214, 166, 248, 108, 237, 216, 71, 244, 173, 72, 133, 82, 6, 143, 240, 104, 41},
    {40, 157, 102, 96, 201, 223, 200, 197, 150, 181, 106, 83, 103, 126, 143, 33, 145, 230, 78, 6, 171, 146, 210, 143, 112, 5, 245, 23, 183, 138, 18, 120},
    {220, 37, 27, 203, 239, 196, 176, 131, 37, 66, 188, 243, 185, 250, 113, 23, 167, 211, 154, 243, 168, 215, 54, 171, 159, 36, 195, 81, 13, 150, 43, 43},
    {232, 121, 176, 222, 183, 196, 159, 90, 238, 193, 105, 52, 101, 167, 244, 170, 121, 114, 196, 6, 67, 152, 80, 185, 221, 7, 83, 105, 176, 208, 224, 121},
    {226, 181, 183, 52, 241, 163, 61, 179, 221, 207, 220, 73, 245, 242, 25, 236, 67, 84, 179, 222, 167, 62, 167, 182, 32, 9, 92, 30, 165, 127, 204, 68},
    {226, 119, 16, 242, 200, 139, 240, 87, 11, 222, 92, 146, 156, 243, 46, 119, 65, 59, 1, 248, 92, 183, 50, 175, 87, 40, 206, 53, 208, 220, 148, 13},
    {70, 240, 79, 112, 54, 157, 228, 146, 74, 122, 216, 88, 232, 62, 158, 13, 14, 146, 115, 117, 176, 222, 90, 225, 244, 23, 94, 190, 150, 7, 136, 96},
    {22, 71, 241, 103, 45, 193, 195, 144, 183, 101, 154, 50, 39, 68, 49, 110, 51, 44, 62, 0, 229, 113, 72, 81, 168, 29, 73, 106, 102, 40, 132, 24},
    {196, 133, 107, 11, 130, 105, 74, 33, 204, 171, 133, 221, 174, 193, 241, 36, 38, 179, 196, 107, 219, 185, 181, 253, 228, 47, 155, 42, 231, 73, 41, 78},
    {58, 255, 225, 197, 115, 208, 160, 143, 39, 197, 82, 69, 143, 235, 92, 170, 74, 40, 57, 11, 171, 227, 26, 185, 217, 207, 90, 185, 197, 190, 35, 60},
    {88, 43, 92, 118, 223, 136, 105, 145, 238, 186, 115, 8, 214, 112, 153, 253, 38, 108, 205, 230, 157, 130, 11, 66, 101, 85, 253, 110, 110, 14, 148, 112},
  };
  int result = 1;

  for (int i=0; i<16; i++) {
    printf("testing ristretto sage vector %d: ", i+1);

    bignum25519 fe;
    ristretto_point_t P, Q;
    uint8_t r;

    curve25519_expand(fe, elements[i]);
    ristretto_flavor_elligator2(&P, fe);
    //ge25519_pack(encoded, &P.point);
    ristretto_encode(encoded, &P);

    r = uint8_32_ct_eq(encoded_images[i], encoded);

    if (1 == r) {
      printf("OKAY\n");
    } else {
      printf("FAIL\n");
#if defined(DEBUGGING)
      printf("Expected = ");
#endif
      print_uchar32(encoded_images[i]);
#if defined(DEBUGGING)
      printf("\n");
      printf("Received = ");
      print_uchar32(&encoded[i]);
      printf("\n");
#endif
    }
    result &= (int)r;
  }
  return result;
}

int main(int argc, char **argv)
{
  int result;

  result  = test_invsqrt_random_field_element();
  result &= test_uint8_32_ct_eq();
  result &= test_ristretto_decode_random_invalid_point();
  result &= test_ristretto_decode_basepoint();
  result &= test_curve25519_expand_random_field_element();
  result &= test_curve25519_expand_basepoint();
  result &= test_curve25519_expand_identity();
  result &= test_ge25519_unpack_pack();
  result &= test_ristretto_encode_identity();
  result &= test_ristretto_encode_basepoint();
  result &= test_ristretto_encode_small_multiples_of_basepoint();
  result &= test_ristretto_ct_eq();
  result &= test_ristretto_flavor_elligator_versus_sage();

  if (0 == result) {
    printf("SOME TESTS FAILED TO PASS\n");
  } else {
    printf("ALL TESTS PASSED OKAY\n");
  }

  return result;
}
