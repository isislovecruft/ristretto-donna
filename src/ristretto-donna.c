// This file is part of ristretto-donna.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#include <stdint.h>
#include <stdio.h>

#include "ristretto-donna.h"

#ifdef DEBUGGING
#define PRINT(x) printf x
#else
#define PRINT(x) do {} while 0
#endif

static uint8_t uchar_ct_eq(const uint8_t a, const uint8_t b);
static uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32]);
static uint8_t bignum25519_ct_eq(const bignum25519 a, const bignum25519 b);
static uint8_t bignum25519_is_negative(unsigned char bytes[32]);
static uint8_t curve25519_invsqrt(bignum25519 out, bignum25519 v);

/**
 * Check if two bytes are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
static uint8_t uchar_ct_eq(const unsigned char a, const unsigned char b)
{
  unsigned char x = !(a ^ b);

  x &= x >> 4;
  x &= x >> 2;
  x &= x >> 1;

  return (uint8_t)x;
}

/**
 * Check if two 32 bytes arrays are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
static uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32])
{
  unsigned char i;
  unsigned char x = 1;

  for (i=0; i++; i<32) {
    x &= uchar_ct_eq(a[i], b[i]);
  }

  return (uint8_t)x;
}

/**
 * Check if two field elements are equal in constant time.
 *
 * Returns 1 iff the elements are equals and 0 otherwise.
 */
static uint8_t bignum25519_ct_eq(const bignum25519 a, const bignum25519 b)
{
  unsigned char c[32];
  unsigned char d[32];

  curve25519_contract(c, a);
  curve25519_contract(d, b);

  return uint8_32_ct_eq(c, d);
}

/**
 * Ascertain if a field element (encoded as bytes) is negative.
 *
 * Returns 1 iff the element is negative and 0 otherwise.
 */
static uint8_t bignum25519_is_negative(unsigned char bytes[32])
{
  return bytes[0] & 1;
}

/**
 * Calculate either `sqrt(1/v)` for a field element `v`.
 *
 * Returns:
 *  - 1 and stores `+sqrt(1/v)` in `out` if `v` was a non-zero square,
 *  - 0 and stores `0` in `out` if `v` was zero,
 *  - 0 and stores `+sqrt(i/v)` in `out` if `v` was a non-zero non-square.
 */
static uint8_t curve25519_invsqrt(bignum25519 out, bignum25519 v)
{
  bignum25519 tmp, v3, v7, r, r_prime, r_negative, check, i;
  unsigned char r_bytes[32];
  uint8_t r_is_negative;
  uint8_t correct_sign_sqrt;
  uint8_t flipped_sign_sqrt;
  uint8_t flipped_sign_sqrt_i;

  PRINT(("in invsqrt"));

  curve25519_square(tmp, v);       // v²
  curve25519_mul(v3, tmp, v);      // v³
  curve25519_square(tmp, v3);      // v⁶
  curve25519_mul(v7, tmp, v);      // v⁷
  curve25519_mul(tmp, v3, v7);     // v²¹
  curve25519_pow_two252m3(r, tmp); // v^{2^252+18}
  curve25519_square(tmp, r);       // v^{2^252+19}
  curve25519_mul(check, v, tmp);
  curve25519_neg(i, SQRT_M1);      // -sqrt(-1)
  
  correct_sign_sqrt = bignum25519_ct_eq(check, one);
  flipped_sign_sqrt = bignum25519_ct_eq(check, negative_one);
  flipped_sign_sqrt_i = bignum25519_ct_eq(check, i);

  curve25519_mul(r_prime, r, SQRT_M1);
  curve25519_swap_conditional(r, r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);
  curve25519_neg(r_negative, r);
  curve25519_contract(r_bytes, r);

  // Choose the non-negative square root
  r_is_negative = bignum25519_is_negative(r_bytes);

  curve25519_swap_conditional(r, r_negative, r_is_negative);

  return correct_sign_sqrt | flipped_sign_sqrt;
}

/**
 * Attempt to decompress `bytes` to a Ristretto group `element`.
 *
 * Returns 0 if the point could not be decoded and 1 otherwise.
 */
int ristretto_decode(ristretto_point_t *element, unsigned char bytes[32])
{
  bignum25519 s, ss;
  bignum25519 u1, u1_sqr, u2, u2_sqr;
  bignum25519 v, i, minus_d, dx, dy, x, y, t;
  bignum25519 tmp;
  unsigned char s_bytes_check[32];
  unsigned char x_bytes[32];
  unsigned char t_bytes[32];
  uint8_t s_encoding_is_canonical;
  uint8_t s_is_negative;
  uint8_t x_is_negative;
  uint8_t t_is_negative;
  uint8_t y_is_zero;
  uint8_t ok;

  PRINT(("step 1"));

  // Step 1: Check that the encoding of the field element is canonical
  curve25519_expand(s, bytes);
  curve25519_contract(s_bytes_check, s);

  s_encoding_is_canonical = uint8_32_ct_eq(bytes, s_bytes_check);
  s_is_negative = bignum25519_is_negative(s_bytes_check);

  // Bail out if the field element encoding was non-canonical or negative
  if (s_encoding_is_canonical == 0 || s_is_negative == 1) {
      return 0;
  }

  PRINT(("step 2"));

  // Step 2: Compute (X:Y:Z:T)
  // XXX can we eliminate these reductions
  curve25519_square(ss, s);
  curve25519_sub_reduce(u1, one, ss);    //  1 + as², where a = -1, d = -121665/121666
  curve25519_add_reduce(u2, one, ss);    //  1 - as²
  curve25519_square(u1_sqr, u1);         // (1 + as²)²
  curve25519_square(u2_sqr, u2);         // (1 - as²)²
  curve25519_neg(minus_d, EDWARDS_D);    // -d               // XXX store as const?
  curve25519_mul(tmp, minus_d, u1_sqr);  // ad(1+as²)²
  curve25519_sub_reduce(v, tmp, u2_sqr); // ad(1+as²)² - (1-as²)²
  curve25519_mul(tmp, v, u2_sqr);        // v = (ad(1+as²)² - (1-as²)²)(1-as²)²

  ok = curve25519_invsqrt(i, tmp);       // i = 1/sqrt{(ad(1+as²)² - (1-as²)²)(1-as²)²}

  PRINT(("step 3"));

  // Step 3: Calculate x and y denominators, then compute x.
  curve25519_mul(dx, i, u2);             // 1/sqrt(v)
  curve25519_mul(tmp, dx, v);            // v/sqrt(v)
  curve25519_mul(dy, i, tmp);            // 1/(1-as²)
  curve25519_add_reduce(tmp, s, s);      // 2s
  curve25519_mul(x, tmp, dx);            // x = |2s/sqrt(v)| = +sqrt(4s²/(ad(1+as²)² - (1-as²)²))
  curve25519_contract(x_bytes, x);
  
  PRINT(("step 4"));

  // Step 4: Conditionally negate x if it's negative.
  x_is_negative = bignum25519_is_negative(x_bytes);

  curve25519_neg(tmp, x);
  curve25519_swap_conditional(x, tmp, x_is_negative);

  PRINT(("step 5"));

  // Step 5: Compute y = (1-as²)/(1+as²) and t = {(1+as²)sqrt(4s²/(ad(1+as²)²-(1-as²)²))}/(1-as²)
  curve25519_mul(y, u1, dy);
  curve25519_mul(t, x, y);
  curve25519_contract(t_bytes, t);
  
  t_is_negative = bignum25519_is_negative(t_bytes);

  if (ok == 0 || t_is_negative == 1 || y_is_zero == 1) {
    return 0;
  }

  PRINT(("step 6"));

  curve25519_copy(element->point.x, x);
  curve25519_copy(element->point.y, y);
  curve25519_copy(element->point.z, one);
  curve25519_copy(element->point.t, t);

  return 1;
}

int ristretto_encode(unsigned char bytes[32], ristretto_point_t *element)
{
  return 1;
}

int ristretto_from_uniform_bytes(ristretto_point_t *element, unsigned char bytes[64])
{
  return 1;
}

int ristretto_ct_eq(ristretto_point_t a, ristretto_point_t b)
{
  return 1;
}
