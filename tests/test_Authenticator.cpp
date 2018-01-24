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
#include "thekogans/util/Types.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/DSA.h"
#include "thekogans/crypto/EC.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Authenticator.h"

using namespace thekogans;

namespace {
    bool TestAuthenticator (
            const char *name,
            crypto::AsymmetricKey::Ptr privateKey) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            crypto::Authenticator signer (crypto::Authenticator::Sign, privateKey);
            util::ui8 buffer[1024];
            util::GlobalRandomSource::Instance ().GetBytes (buffer, 1024);
            util::Buffer::UniquePtr signature = signer.SignBuffer (buffer, 1024);
            crypto::Authenticator verifier (crypto::Authenticator::Verify, privateKey->GetPublicKey ());
            bool result = verifier.VerifyBufferSignature (
                buffer,
                1024,
                signature->GetReadPtr (),
                signature->GetDataAvailableForReading ());
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.what ();
            return false;
        }
    }
}

TEST (thekogans, RSA) {
    crypto::OpenSSLInit openSSLInit;
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::RSA::CreateKey (1024)",
            crypto::RSA::CreateKey (1024)),
        true);
}

TEST (thekogans, DSA) {
    crypto::OpenSSLInit openSSLInit;
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::DSA::ParamsFromKeyLength (512)->CreateAsymmetricKey ()",
            crypto::DSA::ParamsFromKeyLength (512)->CreateKey ()),
        true);
}

TEST (thekogans, EC) {
    crypto::OpenSSLInit openSSLInit;
    // Named curves
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)->CreateKey ()",
            crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)->CreateKey ()),
        true);
    // RFC5114Curve
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)->CreateKey ()",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)->CreateKey ()",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)->CreateKey ()",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)->CreateKey ()",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)->CreateKey ())",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)->CreateKey ()),
        true);
    // RFC5639Curve
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)->CreateKey ()),
        true);
    CHECK_EQUAL (
        TestAuthenticator (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)->CreateKey ())",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)->CreateKey ()),
        true);
}

TESTMAIN
