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
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/HMAC.h"
#include "thekogans/crypto/CMAC.h"

using namespace thekogans;

namespace {
    std::string secret ("password");

    bool TestHMAC (
            const char *name,
            crypto::SymmetricKey::SharedPtr key,
            const EVP_MD *md) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            crypto::HMAC mac (key, md);
            util::ui8 buffer[1024];
            util::RandomSource::Instance ()->GetBytes (buffer, 1024);
            util::Buffer::SharedPtr signature = mac.SignBuffer (buffer, 1024);
            bool result = mac.VerifyBufferSignature (
                buffer,
                1024,
                signature->GetReadPtr (),
                signature->GetDataAvailableForReading ());
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }

    bool TestCMAC (
            const char *name,
            crypto::SymmetricKey::SharedPtr key,
            const EVP_CIPHER *cipher) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            crypto::CMAC mac (key, cipher);
            util::ui8 buffer[1024];
            util::RandomSource::Instance ()->GetBytes (buffer, 1024);
            util::Buffer::SharedPtr signature = mac.SignBuffer (buffer, 1024);
            bool result = mac.VerifyBufferSignature (
                buffer,
                1024,
                signature->GetReadPtr (),
                signature->GetDataAvailableForReading ());
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }
}

TEST (thekogans, HMAC) {
    crypto::OpenSSLInit openSSLInit;
    crypto::SymmetricKey::SharedPtr key = crypto::SymmetricKey::FromSecretAndSalt (
        secret.c_str (),
        secret.size ());
    const std::vector<std::string> &messageDigests =
        crypto::CipherSuite::GetMessageDigests ();
    for (std::size_t i = 0, count = messageDigests.size (); i < count; ++i) {
        CHECK_EQUAL (
            TestHMAC (
                std::string ("HMAC-" + messageDigests[i]).c_str (),
                key,
                crypto::CipherSuite::GetOpenSSLMessageDigestByName (messageDigests[i])),
            true);
    }
}

TEST (thekogans, CMAC) {
    crypto::OpenSSLInit openSSLInit;
    const std::vector<std::string> &ciphers =
        crypto::CipherSuite::GetCiphers ();
    for (std::size_t i = 0, count = ciphers.size (); i < count; ++i) {
        const EVP_CIPHER *cipher = crypto::CipherSuite::GetOpenSSLCipherByName (ciphers[i]);
        CHECK_EQUAL (
            TestCMAC (
                std::string ("CMAC-" + ciphers[i]).c_str (),
                crypto::SymmetricKey::FromSecretAndSalt (
                    secret.c_str (),
                    secret.size (),
                    0,
                    0,
                    crypto::GetCipherKeyLength (cipher)),
                cipher),
            true);
    }
}

TESTMAIN
