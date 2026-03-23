cmake_minimum_required(VERSION 3.20)

project(
    decrypt_openssl_cpp
    VERSION 1.0.0
    DESCRIPTION "Decrypt OpenSSL salted AES-256-CBC payloads in memory"
    LANGUAGES CXX
)

option(DECRYPT_OPENSSL_WITH_QT "Build the optional Qt adapter target" OFF)
option(DECRYPT_OPENSSL_BUILD_EXAMPLES "Build example executables" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(
    decrypt_openssl
    src/decrypt.cpp
    src/openssl_format.cpp
    src/key_derivation.cpp
    src/decryptor.cpp
)

add_library(decrypt_openssl::decrypt_openssl ALIAS decrypt_openssl)

target_include_directories(
    decrypt_openssl
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(decrypt_openssl PUBLIC cxx_std_20)
target_link_libraries(decrypt_openssl PUBLIC OpenSSL::Crypto)

if(DECRYPT_OPENSSL_WITH_QT)
    find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

    add_library(
        decrypt_openssl_qt
        src/qt_decrypt.cpp
    )

    add_library(decrypt_openssl::decrypt_openssl_qt ALIAS decrypt_openssl_qt)

    target_include_directories(
        decrypt_openssl_qt
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )

    target_compile_features(decrypt_openssl_qt PUBLIC cxx_std_20)
    target_link_libraries(
        decrypt_openssl_qt
        PUBLIC
            decrypt_openssl
            Qt${QT_VERSION_MAJOR}::Core
    )
endif()

include(CTest)

if(BUILD_TESTING)
    add_executable(
        decrypt_openssl_tests
        tests/decrypt_tests.cpp
    )

    target_include_directories(
        decrypt_openssl_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(decrypt_openssl_tests PRIVATE decrypt_openssl)

    add_test(NAME decrypt_openssl_tests COMMAND decrypt_openssl_tests)
endif()

if(DECRYPT_OPENSSL_BUILD_EXAMPLES)
    add_executable(
        decrypt_openssl_example
        examples/decrypt_example.cpp
    )

    target_link_libraries(decrypt_openssl_example PRIVATE decrypt_openssl)

    if(BUILD_TESTING)
        add_test(NAME decrypt_openssl_example_runs COMMAND decrypt_openssl_example)
    endif()
endif()
