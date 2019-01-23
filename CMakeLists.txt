cmake_minimum_required (VERSION 2.6)
project (ristretto_donna)

# The version number.
set (ristretto_donna_VERSION_MAJOR 0)
set (ristretto_donna_VERSION_MINOR 1)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/src/ristretto-donna-config.h.in"
  "${PROJECT_BINARY_DIR}/src/ristretto-donna-config.h"
  )

# Add the src/ directory
add_subdirectory(src)

# add the binary tree to the search path for include files
# so that we will find ristretto-donna-config.h
include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -O3 -DEDD25519_TEST -DDEBUGGING")

# add the executable
add_executable(ristretto-donna
  src/ristretto-donna.c
  src/test-ristretto.c
)

# Link in OpenSSL
target_link_libraries(ristretto-donna -lssl)
target_link_libraries(ristretto-donna -lcrypto)
