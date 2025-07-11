cmake_minimum_required(VERSION 3.10)
project(pkcs11-proxy C)
# Ensure compatibility with older CMake policies
if (COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif()

# Set build options
option(ENABLE_DEBUG "Enable debug symbols (default: ON)" ON)
option(ENABLE_DEBUG_OUTPUT "Enable debug output (default: OFF)" OFF)
option(ENABLE_OPTIMIZATION "Enable optimizations (default: ON)" ON)

# Convert boolean to 0/1 for config.h
if(ENABLE_DEBUG_OUTPUT)
    set(DEBUG_OUTPUT_VALUE 1)
else()
    set(DEBUG_OUTPUT_VALUE 0)
endif()

# Generate config.h
configure_file(${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/config.h)
include_directories(${CMAKE_BINARY_DIR})

# Set source files for the proxy and daemon
set(PKCS11_PROXY_SRCS
    gck-rpc-conf.c
    gck-rpc-module.c
    gck-rpc-message.c
    gck-rpc-util.c
    egg-buffer.c
    gck-rpc-tls-psk.c
)

set(PKCS11_DAEMON_SRCS
    egg-buffer.c
    gck-rpc-conf.c
    gck-rpc-daemon-standalone.c
    gck-rpc-dispatch.c
    gck-rpc-message.c
    gck-rpc-util.c
    syscall-reporter.c
    syscall-names.h
    gck-rpc-tls-psk.c
)

# Compiler flags
add_compile_options(-Wall)

# Include debug symbols
if (ENABLE_DEBUG)
    add_compile_options(-g)
endif()

# Enable optimization
if (ENABLE_OPTIMIZATION)
    add_compile_options(-O2)
endif()

# Find and link OpenSSL (require 1.1.1+)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl>=1.1.1)

# Ensure linker uses pkg-config paths explicitly
include_directories(${OPENSSL_INCLUDE_DIRS})
link_directories(${OPENSSL_LIBRARY_DIRS}) # Ensure library paths are included

# Define shared library for pkcs11-proxy
add_library(pkcs11-proxy SHARED ${PKCS11_PROXY_SRCS})
set_target_properties(pkcs11-proxy PROPERTIES VERSION 0.1 SOVERSION 0)

# Link OpenSSL and other necessary libraries
target_link_libraries(pkcs11-proxy ${OPENSSL_LIBRARIES} pthread)

# Define executable for pkcs11-daemon
if (WIN32)
    set(GUI_TYPE "")
    if ("${CMAKE_BUILD_TYPE}" MATCHES "^Rel.*")
        set(GUI_TYPE WIN32)
    endif()
    add_executable(pkcs11-daemon ${GUI_TYPE} ${PKCS11_DAEMON_SRCS})
else()
    add_executable(pkcs11-daemon ${PKCS11_DAEMON_SRCS})
endif()

# Link OpenSSL and other necessary libraries to the daemon
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(pkcs11-daemon ${OPENSSL_LIBRARIES} dl pthread seccomp)
else()
    target_link_libraries(pkcs11-daemon ${OPENSSL_LIBRARIES} dl pthread)
endif()

# Win32-specific settings (if required)
if (WIN32)
    include_directories("ext/include")

    add_library(dl STATIC IMPORTED)
    set_property(TARGET dl PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/ext/lib/libdl.a)

    target_link_libraries(pkcs11-daemon ws2_32)
    target_link_libraries(pkcs11-proxy ws2_32)
endif()

# Install directives
install(TARGETS pkcs11-proxy DESTINATION lib)
install(TARGETS pkcs11-daemon DESTINATION bin)

# Generate syscall-names.h using a custom command
add_custom_command(
    OUTPUT syscall-names.h
    COMMAND ${CMAKE_SOURCE_DIR}/mksyscalls.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS mksyscalls.sh
    COMMENT "Generating syscall-names.h"
)
