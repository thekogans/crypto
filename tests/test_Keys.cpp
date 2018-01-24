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
            key1.GetDataAvailableForReading () == key2.GetDataAvailableForReading () &&
            crypto::TimeInsensitiveCompare (
                key1.GetReadPtr (),
                key2.GetReadPtr (),
                key1.GetDataAvailableForReading ());
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
        util::Buffer serializer (util::NetworkEndian, (util::ui32)key1->Size (false));
        key1->Serialize (serializer, false);
        crypto::SymmetricKey::Ptr key2 (new crypto::SymmetricKey (serializer));
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
        util::Buffer serializer (util::NetworkEndian, (util::ui32)key1->Size ());
        key1->Serialize (serializer);
        crypto::SymmetricKey::Ptr key2 =
            util::dynamic_refcounted_pointer_cast<crypto::SymmetricKey> (
                crypto::Serializable::Get (serializer));
        bool result = key2.Get () != 0 && *key1 == *key2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
}

namespace {
    bool operator == (
            const crypto::AsymmetricKey &key1,
            const crypto::AsymmetricKey &key2) {
        return
            key1.GetId () == key2.GetId () &&
            key1.GetName () == key2.GetName () &&
            key1.GetDescription () == key2.GetDescription ();
    }
}

TEST (thekogans, AsymmetricKey) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::Ptr privateKey =
        crypto::DSA::ParamsFromKeyLength (512)->CreateKey ();
    {
        std::cout << "AsymmetricKey private key...";
        util::Buffer serializer (util::NetworkEndian, (util::ui32)privateKey->Size (false));
        privateKey->Serialize (serializer, false);
        crypto::AsymmetricKey::Ptr privateKey2 (new crypto::AsymmetricKey (serializer));
        bool result = *privateKey == *privateKey2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
    {
        std::cout << "AsymmetricKey public key...";
        crypto::AsymmetricKey::Ptr publicKey = privateKey->GetPublicKey ();
        util::Buffer serializer (util::NetworkEndian, (util::ui32)publicKey->Size (false));
        publicKey->Serialize (serializer, false);
        crypto::AsymmetricKey::Ptr publicKey2 (new crypto::AsymmetricKey (serializer));
        bool result = *publicKey == *publicKey2;
        std::cout << (result ? "pass" : "fail") << std::endl;
        CHECK_EQUAL (result, true);
    }
}

TESTMAIN
