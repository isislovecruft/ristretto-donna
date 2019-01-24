// This file is part of ristretto-donna.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#ifndef RISTRETTO_UTILS_H
#define RISTRETTO_UTILS_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef DEBUGGING
#define PRINT(x)                                         \
  printf(x);                                             \
  printf("\n");
#else
#define PRINT(x) do {} while (0)
#endif

#ifdef __GNUC__
#define FREE(p)                                          \
  typeof(&(p)) tmpvar = &(p);                            \
  free(*tmpvar);                                         \
  *tmpvar=NULL;
#else
#define FREE(p)                                          \
  free(p);                                               \
  (p)=NULL;
#endif

#ifdef ED25519_TEST
#define STATIC
#define EXTERN(type, name) extern type name;
#else
#define STATIC static
#define EXTERN(type, name)
#endif /* defined(ED25519_TEST) */

#if defined(__cplusplus)
}
#endif

#endif // RISTRETTO_UTILS_H
