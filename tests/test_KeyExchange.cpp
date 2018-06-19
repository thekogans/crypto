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
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/DHEKeyExchange.h"
#include "thekogans/crypto/RSAKeyExchange.h"

using namespace thekogans;

namespace {
    bool operator == (
            const crypto::SymmetricKey &key1,
            const crypto::SymmetricKey &key2) {
        return memcmp (key1.Get ().data, key2.Get ().data, EVP_MAX_KEY_LENGTH) == 0;
    }

    bool TestDHE (
            const char *paramsName,
            crypto::Params::Ptr params) {
        THEKOGANS_UTIL_TRY {
            std::cout << paramsName << "...";
            crypto::DHEKeyExchange keyExchange1 (crypto::ID (), params);
            crypto::DHEKeyExchange keyExchange2 (crypto::ID (), params);
            crypto::SymmetricKey::Ptr key1 =
                keyExchange1.DeriveSharedSymmetricKey (keyExchange2.GetParams ());
            crypto::SymmetricKey::Ptr key2 =
                keyExchange2.DeriveSharedSymmetricKey (keyExchange1.GetParams ());
            bool result = *key1 == *key2;
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.what ();
            return false;
        }
    }

    bool TestRSA (
            const char *keyName,
            crypto::AsymmetricKey::Ptr publicKey,
            crypto::AsymmetricKey::Ptr privateKey) {
        THEKOGANS_UTIL_TRY {
            std::cout << keyName << "...";
            crypto::RSAKeyExchange keyExchange1 (crypto::ID (), publicKey);
            crypto::RSAKeyExchange::Params::Ptr params1 = keyExchange1.GetParams ();
            crypto::RSAKeyExchange keyExchange2 (crypto::ID (), privateKey, params1);
            crypto::SymmetricKey::Ptr key1 =
                keyExchange1.DeriveSharedSymmetricKey (keyExchange2.GetParams ());
            crypto::SymmetricKey::Ptr key2 =
                keyExchange2.DeriveSharedSymmetricKey (params1);
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
        TestDHE (
            "crypto::DH::ParamsFromPrimeLengthAndGenerator (512)",
            crypto::DH::ParamsFromPrimeLengthAndGenerator (512)),
        true);
    // crypto::DH::RFC3526Prime
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192)),
        true);
    // crypto::DH::RFC5114Prime
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256)),
        true);
}

TEST (thekogans, EC) {
    crypto::OpenSSLInit openSSLInit;
    // Named curves
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)",
            crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)),
        true);
    // RFC5114Curve
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)),
        true);
    // RFC5639Curve
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)),
        true);
}

TEST (thekogans, RSA) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::Ptr privateKey = crypto::RSA::CreateKey (1536);
    CHECK_EQUAL (
        TestRSA (
            "crypto::RSA::CreateKey (1536)",
            privateKey->GetPublicKey (),
            privateKey),
        true);
}

TESTMAIN
