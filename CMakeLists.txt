if(WIN32)
    add_definitions(
        -DTOOLCHAIN_OS_Windows
        -D_LIB_THEKOGANS_CRYPTO_BUILD)
    remove_definitions(
        -DUNICODE
        -D_UNICODE)
endif()

if(APPLE)
    add_definitions(-DTOOLCHAIN_OS_OSX)
endif()

# TODO (rbosa): Please automate the pickup of the version numbers from 'thekogans_make.xml'
add_definitions(
    -DTOOLCHAIN_ARCH_x86_64
    -DTHEKOGANS_CRYPTO_MAJOR_VERSION=0
    -DTHEKOGANS_CRYPTO_MINOR_VERSION=2
    -DTHEKOGANS_CRYPTO_PATCH_VERSION=0)

if(KRAGLE_DEPS)
    add_definitions(-DTHEKOGANS_CRYPTO_HAVE_OPENSSL)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DTOOLCHAIN_CONFIG_Debug)
else()
    add_definitions(-DTOOLCHAIN_CONFIG_Release)
endif()

file(GLOB_RECURSE HEADERS "include/thekogans/crypto/*.h")
set(SOURCES
    src/AsymmetricKey.cpp
    src/Authenticator.cpp
    src/CMAC.cpp
    src/Cipher.cpp
    src/CipherSuite.cpp
    src/DH.cpp
    src/DSA.cpp
    src/EC.cpp
    src/HMAC.cpp
    src/ID.cpp
    src/KeyExchange.cpp
    src/KeyRing.cpp
    src/MAC.cpp
    src/MessageDigest.cpp
    src/OpenSSLInit.cpp
    src/OpenSSLUtils.cpp
    src/Params.cpp
    src/RSA.cpp
    src/Serializable.cpp
    src/Serializables.cpp
    src/SymmetricKey.cpp
    src/SystemCACertificates.cpp
    src/Version.cpp)

add_library(thekogans_crypto ${HEADERS} ${SOURCES})

# Link against the dependencies defined by Kragle, if this library is used in kragle
# You might want to setup your own linkage for your project...
if(KRAGLE_DEPS)
    target_link_libraries(thekogans_crypto
        thekogans_util
        openssl_lib
        zlib_lib)
endif()

target_include_directories(thekogans_crypto PUBLIC include)
