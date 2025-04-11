// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_crypto.
//
// libthekogans_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_crypto. If not, see <http://www.gnu.org/licenses/>.

#include <iostream>
#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    #include <argon2.h>
#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
#include <CppUnitXLite/CppUnitXLite.cpp>
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/DSA.h"

using namespace thekogans;

namespace {
    std::string secret ("password");
    std::string salt ("saltsalt");

    bool operator == (
            const crypto::SymmetricKey &key1,
            const crypto::SymmetricKey &key2) {
        return
            key1.GetId () == key2.GetId () &&
            key1.GetName () == key2.GetName () &&
            key1.GetDescription () == key2.GetDescription () &&
            key1.Get ().Size () == key2.Get ().Size () &&
            crypto::TimeInsensitiveCompare (
                key1.Get (),
                key2.Get (),
                key1.Get ().Size ());
    }
}

TEST (thekogans, SymmetricKey) {
    crypto::OpenSSLInit openSSLInit;
#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    {
        std::cout << "SymmetricKey::FromArgon2...";
        argon2_context context = {
            0, 0,
            (uint8_t *)secret.data (),
            (uint32_t)secret.size (),
            (uint8_t *)salt.data (),
            (uint32_t)salt.size (),
            0, 0,
            0, 0,
            2,
            1 << 16,
            1,
            1,
            ARGON2_VERSION_13,
            0, 0,
            ARGON2_DEFAULT_FLAGS
        };
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromArgon2 (
                context,
                crypto::GetCipherKeyLength (),
                argon2i_ctx,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    {
        std::cout << "SymmetricKey::FromPBKDF1...";
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromPBKDF1 (
                secret.c_str (),
                secret.size (),
                salt.c_str (),
                salt.size (),
                crypto::GetCipherKeyLength (),
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                1.0,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "SymmetricKey::FromPBKDF2...";
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromPBKDF2 (
                secret.c_str (),
                secret.size (),
                salt.c_str (),
                salt.size (),
                crypto::GetCipherKeyLength (),
                crypto::SymmetricKey::PBKDF2_HMAC_SHA256,
                1,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "SymmetricKey::FromOpenSSLPBKDF2...";
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromOpenSSLPBKDF2 (
                secret.c_str (),
                secret.size (),
                salt.c_str (),
                salt.size (),
                crypto::GetCipherKeyLength (),
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "SymmetricKey::FromSecretAndSalt...";
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromSecretAndSalt (
                secret.c_str (),
                secret.size (),
                salt.c_str (),
                salt.size (),
                crypto::GetCipherKeyLength (),
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "SymmetricKey::FromRandom...";
        crypto::SymmetricKey::SharedPtr key1 =
            crypto::SymmetricKey::FromRandom (
                crypto::SymmetricKey::MIN_RANDOM_LENGTH,
                0,
                0,
                crypto::GetCipherKeyLength (),
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                crypto::ID (),
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, key1->GetSize ());
        serializer << *key1;
        crypto::SymmetricKey::SharedPtr key2;
        serializer >> key2;
        bool result = key2.Get () != 0 && *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
}

TESTMAIN
