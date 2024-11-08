cmake_minimum_required(VERSION 3.1)
project(pkcs11-proxy C)

# Ensure compatibility with older CMake policies
if (COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif()

# Set source files for the proxy and daemon
set(PKCS11_PROXY_SRCS
    gck-rpc-module.c
    gck-rpc-message.c
    gck-rpc-util.c
    egg-buffer.c
    gck-rpc-tls-psk.c
)

set(PKCS11_DAEMON_SRCS
    egg-buffer.c
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

# Define shared library for pkcs11-proxy
add_library(pkcs11-proxy SHARED ${PKCS11_PROXY_SRCS})
set_target_properties(pkcs11-proxy PROPERTIES VERSION 0.1 SOVERSION 0)

# Define executable for pkcs11-daemon
if (WIN32)
    # Disable console for release build on Win32
    set(GUI_TYPE "")
    if ("${CMAKE_BUILD_TYPE}" MATCHES "^Rel.*")
        set(GUI_TYPE WIN32)
    endif()
    add_executable(pkcs11-daemon ${GUI_TYPE} ${PKCS11_DAEMON_SRCS})
else()
    add_executable(pkcs11-daemon ${PKCS11_DAEMON_SRCS})
endif()

# Find and link OpenSSL (require 1.1.1+)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl>=1.1.1)

# Include directories and link libraries
target_include_directories(pkcs11-proxy PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_include_directories(pkcs11-daemon PRIVATE ${OPENSSL_INCLUDE_DIRS})

target_link_libraries(pkcs11-proxy ${OPENSSL_LIBRARIES} pthread)
target_link_libraries(pkcs11-daemon ${OPENSSL_LIBRARIES} dl pthread seccomp)

if (WIN32)
    # Additional Win32 libraries and paths
    include_directories("ext/include")
    
    # Static library for `dl`
    add_library(dl STATIC IMPORTED)
    set_property(TARGET dl PROPERTY IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/ext/lib/libdl.a)
    
    target_link_libraries(pkcs11-daemon ws2_32)
    target_link_libraries(pkcs11-proxy ws2_32)
endif()

# Install directives
install(TARGETS pkcs11-proxy DESTINATION /lib)
install(TARGETS pkcs11-daemon DESTINATION /bin)

# Generate syscall-names.h using a custom command
add_custom_command(
    OUTPUT syscall-names.h
    COMMAND ${CMAKE_SOURCE_DIR}/mksyscalls.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS mksyscalls.sh
    COMMENT "Generating syscall-names.h"
)
