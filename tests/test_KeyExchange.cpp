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
#include "thekogans/util/Exception.h"
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
        util::Buffer key1Buffer (util::HostEndian, util::Serializable::Size (key1));
        key1Buffer << key1;
        util::Buffer key2Buffer (util::HostEndian, util::Serializable::Size (key2));
        key2Buffer << key2;
        return key1Buffer.GetDataAvailableForReading () == key2Buffer.GetDataAvailableForReading () &&
            memcmp (
                key1Buffer.GetReadPtr (),
                key2Buffer.GetReadPtr (),
                key1Buffer.GetDataAvailableForReading ()) == 0;
    }

    bool TestDHE (
            const char *paramsName,
            crypto::Params::SharedPtr params,
            crypto::AsymmetricKey::SharedPtr /*privateKey1*/,
            crypto::AsymmetricKey::SharedPtr /*privateKey2*/) {
        THEKOGANS_UTIL_TRY {
            std::cout << paramsName << "...";
            crypto::DHEKeyExchange keyExchange1 (crypto::ID (), params);
            crypto::DHEKeyExchange::Params::SharedPtr params1 = keyExchange1.GetParams ();
            crypto::DHEKeyExchange keyExchange2 (params1);
            crypto::SymmetricKey::SharedPtr key1 =
                keyExchange1.DeriveSharedSymmetricKey (keyExchange2.GetParams ());
            crypto::SymmetricKey::SharedPtr key2 =
                keyExchange2.DeriveSharedSymmetricKey (params1);
            bool result = *key1 == *key2;
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }

    bool TestRSA (
            const char *keyName,
            crypto::AsymmetricKey::SharedPtr publicKey,
            crypto::AsymmetricKey::SharedPtr privateKey) {
        THEKOGANS_UTIL_TRY {
            std::cout << keyName << "...";
            crypto::RSAKeyExchange keyExchange1 (crypto::ID (), publicKey);
            crypto::RSAKeyExchange::Params::SharedPtr params1 = keyExchange1.GetParams ();
            crypto::RSAKeyExchange keyExchange2 (privateKey, params1);
            crypto::SymmetricKey::SharedPtr key1 =
                keyExchange1.DeriveSharedSymmetricKey (keyExchange2.GetParams ());
            crypto::SymmetricKey::SharedPtr key2 =
                keyExchange2.DeriveSharedSymmetricKey (params1);
            bool result = *key1 == *key2;
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }
}

TEST (thekogans, DH) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::SharedPtr privateKey1 = crypto::RSA::CreateKey (512);
    crypto::AsymmetricKey::SharedPtr privateKey2 = crypto::RSA::CreateKey (512);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromPrimeLengthAndGenerator (512)",
            crypto::DH::ParamsFromPrimeLengthAndGenerator (512),
            privateKey1,
            privateKey2),
        true);
    // crypto::DH::RFC3526Prime
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192),
            privateKey1,
            privateKey2),
        true);
    // crypto::DH::RFC5114Prime
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256),
            privateKey1,
            privateKey2),
        true);
}

TEST (thekogans, EC) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::SharedPtr privateKey1 = crypto::RSA::CreateKey (512);
    crypto::AsymmetricKey::SharedPtr privateKey2 = crypto::RSA::CreateKey (512);
    // Named curves
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)",
            crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1),
            privateKey1,
            privateKey2),
        true);
    // RFC5114Curve
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521),
            privateKey1,
            privateKey2),
        true);
    // RFC5639Curve
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T),
            privateKey1,
            privateKey2),
        true);
    CHECK_EQUAL (
        TestDHE (
            "crypto::EC::ParamsFromX25519Curve ()",
            crypto::EC::ParamsFromX25519Curve (),
            privateKey1,
            privateKey2),
        true);
}

TEST (thekogans, RSA) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::SharedPtr privateKey = crypto::RSA::CreateKey (512);
    CHECK_EQUAL (
        TestRSA (
            "crypto::RSA::CreateKey (512)",
            privateKey->GetPublicKey (),
            privateKey),
        true);
}

TESTMAIN
