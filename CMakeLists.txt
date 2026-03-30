# =============================================================================
# Generic TLS Library (gtls) - Top-level CMake configuration
# =============================================================================
cmake_minimum_required(VERSION 3.14)
project(gtls
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "Generic TLS library with multi-tunnel connection pool support"
)

# ---------------------------------------------------------------------------
# C++ standard configuration
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------
option(ENABLE_ASAN "Enable AddressSanitizer for memory safety checks" OFF)
option(BUILD_TESTS "Build unit and property-based tests" ON)
option(BUILD_EXAMPLES "Build example programs" ON)

# ---------------------------------------------------------------------------
# AddressSanitizer configuration
# ---------------------------------------------------------------------------
if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
endif()

# ---------------------------------------------------------------------------
# Find OpenSSL
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# ---------------------------------------------------------------------------
# gtls library target (placeholder — sources added in later tasks)
# ---------------------------------------------------------------------------
add_library(gtls STATIC)

target_include_directories(gtls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(gtls
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_features(gtls PUBLIC cxx_std_17)

# Library source files
target_sources(gtls PRIVATE
    src/library.cpp
    src/logger.cpp
    src/tls_config.cpp
    src/config_parser.cpp
    src/config_serializer.cpp
    src/tls_context.cpp
    src/certificate_verifier.cpp
    src/tls_connection.cpp
    src/tls_io.cpp
    src/rekey_manager.cpp
    src/connection_pool.cpp
    src/protocol_adapter.cpp
    src/selfie_cache.cpp
)

# ---------------------------------------------------------------------------
# Testing (Google Test + RapidCheck via FetchContent)
# ---------------------------------------------------------------------------
if(BUILD_TESTS)
    enable_testing()
    include(FetchContent)

    # Google Test
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    # Prevent GoogleTest from overriding compiler/linker settings on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # RapidCheck
    FetchContent_Declare(
        rapidcheck
        GIT_REPOSITORY https://github.com/emil-e/rapidcheck.git
        GIT_TAG        master
    )
    set(RC_ENABLE_GTEST ON CACHE BOOL "Enable RapidCheck GTest integration" FORCE)
    FetchContent_MakeAvailable(rapidcheck)

    # Test executable — sources added incrementally per task
    add_executable(gtls_tests
        tests/main_test.cpp
        tests/logger_test.cpp
        tests/tls_config_test.cpp
        tests/tls_context_test.cpp
        tests/certificate_verifier_test.cpp
        tests/tls_connection_test.cpp
        tests/tls_io_test.cpp
        tests/rekey_manager_test.cpp
    )
    target_link_libraries(gtls_tests
        PRIVATE
            gtls
            GTest::gtest
            GTest::gtest_main
            rapidcheck
            rapidcheck_gtest
    )
    target_include_directories(gtls_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${rapidcheck_SOURCE_DIR}/extras/gtest/include
    )
    # Define GTLS_SOURCE_DIR so tests can locate test certificates
    target_compile_definitions(gtls_tests
        PRIVATE
            GTLS_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )

    include(GoogleTest)
    gtest_discover_tests(gtls_tests)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(BUILD_EXAMPLES)
    # RadSec (RADIUS over TLS) demo — illustrates multi-tunnel routing
    add_executable(radius_demo examples/radius_demo.cpp)
    target_link_libraries(radius_demo PRIVATE gtls)
    target_include_directories(radius_demo
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
endif()
