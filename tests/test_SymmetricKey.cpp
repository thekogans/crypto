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
#include <CppUnitXLite/CppUnitXLite.cpp>
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/DSA.h"

using namespace thekogans;

namespace {
    std::string secret ("password");
    std::string salt ("salt");

    bool operator == (
            const crypto::SymmetricKey &key1,
            const crypto::SymmetricKey &key2) {
        return
            key1.GetId () == key2.GetId () &&
            key1.GetName () == key2.GetName () &&
            key1.GetDescription () == key2.GetDescription () &&
            key1.Get ().GetDataAvailableForReading () == key2.Get ().GetDataAvailableForReading () &&
            crypto::TimeInsensitiveCompare (
                key1.Get ().GetReadPtr (),
                key2.Get ().GetReadPtr (),
                key1.Get ().GetDataAvailableForReading ());
    }
}

TEST (thekogans, SymmetricKey) {
    crypto::OpenSSLInit openSSLInit;
    {
        std::cout << "SymmetricKey::FromSecretAndSalt...";
        crypto::SymmetricKey::Ptr key1 =
            crypto::SymmetricKey::FromSecretAndSalt (
                32,
                secret.c_str (),
                secret.size (),
                salt.c_str (),
                salt.size (),
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, (util::ui32)util::Serializable::Size (*key1));
        serializer << *key1;
        crypto::SymmetricKey::Ptr key2;
        serializer >> key2;
        bool result = *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "SymmetricKey::FromRandom...";
        crypto::SymmetricKey::Ptr key1 =
            crypto::SymmetricKey::FromRandom (
                32,
                crypto::SymmetricKey::MIN_RANDOM_LENGTH,
                0,
                0,
                THEKOGANS_CRYPTO_DEFAULT_MD,
                1,
                "test",
                "test key");
        util::Buffer serializer (util::NetworkEndian, (util::ui32)util::Serializable::Size (*key1));
        serializer << *key1;
        crypto::SymmetricKey::Ptr key2;
        serializer >> key2;
        bool result = key2.Get () != 0 && *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
}

TESTMAIN
