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
#include "thekogans/crypto/DH.h"
#include "thekogans/crypto/EC.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/KeyExchange.h"

using namespace thekogans;

namespace {
    bool operator == (
            const crypto::SymmetricKey &key1,
            const crypto::SymmetricKey &key2) {
        return memcmp (key1.data, key2.data, EVP_MAX_KEY_LENGTH) == 0;
    }

    bool TestParams (
            const char *paramsName,
            EVP_PKEY &params,
            std::size_t keyLength) {
        THEKOGANS_UTIL_TRY {
            std::cout << paramsName << "...";
            crypto::AsymmetricKey::Ptr privateKey1 = crypto::AsymmetricKey::FromParams (params);
            crypto::AsymmetricKey::Ptr publicKey1 = privateKey1->GetPublicKey ();
            crypto::AsymmetricKey::Ptr privateKey2 = crypto::AsymmetricKey::FromParams (params);
            crypto::AsymmetricKey::Ptr publicKey2 = privateKey2->GetPublicKey ();
            crypto::KeyExchange keyExchange1 (privateKey1);
            crypto::SymmetricKey::Ptr key1 = keyExchange1.DeriveSharedSymmetricKey (publicKey2, keyLength);
            crypto::KeyExchange keyExchange2 (privateKey2);
            crypto::SymmetricKey::Ptr key2 = keyExchange2.DeriveSharedSymmetricKey (publicKey1, keyLength);
            bool result = *key1 == *key2;
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.what ();
            return false;
        }
    }
}

TEST (thekogans, DH) {
    crypto::OpenSSLInit openSSLInit;
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromPrimeLengthAndGenerator (512)",
            *crypto::DH::ParamsFromPrimeLengthAndGenerator (512),
            32),
        true);
    // crypto::DH::RFC3526Prime
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192)",
            *crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192),
            32),
        true);
    // crypto::DH::RFC5114Prime
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024)",
            *crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224)",
            *crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256)",
            *crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256),
            32),
        true);
}

TEST (thekogans, EC) {
    crypto::OpenSSLInit openSSLInit;
    // Named curves
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)",
            *crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1),
            32),
        true);
    // RFC5114Curve
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)",
            *crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)",
            *crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)",
            *crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)",
            *crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)",
            *crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521),
            32),
        true);
    // RFC5639Curve
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512),
            32),
        true);
    CHECK_EQUAL (
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)",
            *crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T),
            32),
        true);
}

TESTMAIN
