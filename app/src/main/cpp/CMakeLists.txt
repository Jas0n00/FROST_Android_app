cmake_minimum_required(VERSION 3.22.1)
project("frost")

# Specify the absolute OpenSSL directory paths
set(OPENSSL_INCLUDE_DIR "/home/jakub/openssl-install/include")
set(OPENSSL_LIB_DIR "/home/jakub/openssl-install/lib")

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

# Define the source files
file(GLOB SOURCES "${CMAKE_SOURCE_DIR}/src/*.c")  # Adjust the path if needed
file(GLOB HEADERS "${CMAKE_SOURCE_DIR}/headers/*.h")  # Collect header files

# Check if the OpenSSL libraries exist
if(NOT EXISTS "${OPENSSL_LIB_DIR}/libcrypto.a" OR NOT EXISTS "${OPENSSL_LIB_DIR}/libssl.a")
    message(FATAL_ERROR "Could not find OpenSSL libraries in ${OPENSSL_LIB_DIR}")
endif()

# Create the shared library from the sources
add_library(${CMAKE_PROJECT_NAME} SHARED ${SOURCES})

# Link against OpenSSL libraries and Android-specific libraries
target_link_libraries(
        ${CMAKE_PROJECT_NAME}
        "${OPENSSL_LIB_DIR}/libcrypto.a"
        "${OPENSSL_LIB_DIR}/libssl.a"
        log  # Android logging library
)

# Set compilation flags similar to those in your Makefile
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -Wall -Wextra -g)

# Optional: Include headers in the target
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
