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
#add_subdirectory(src)

# add the binary tree to the search path for include files
# so that we will find ristretto-donna-config.h
include_directories("${PROJECT_BINARY_DIR}")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DEDD25519_TEST -DDEBUGGING")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native -O3 -DEDD25519_TEST -DDEBUGGING -DRISTRETTO_DONNA_PRIVATE")

# Define the ristretto-donna library
add_library(ristretto-donna SHARED src/ed25519.c src/ristretto-donna.c)

# Define the test binary
add_executable(ristretto-donna-test src/test-ristretto.c)
target_link_libraries(ristretto-donna-test ristretto-donna)

# Link in OpenSSL
target_link_libraries(ristretto-donna-test -lssl)
target_link_libraries(ristretto-donna-test -lcrypto)
