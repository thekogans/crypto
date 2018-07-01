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
#include "thekogans/crypto/MAC.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/CMAC.h"
#include "thekogans/crypto/HMAC.h"

using namespace thekogans;

namespace {
    std::string secret ("password");

    bool TestMAC (
            const char *name,
            crypto::AsymmetricKey::Ptr key,
            const EVP_MD *md) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            crypto::MAC mac (key, md);
            util::ui8 buffer[1024];
            util::GlobalRandomSource::Instance ().GetBytes (buffer, 1024);
            util::Buffer::UniquePtr signature = mac.SignBuffer (buffer, 1024);
            bool result = mac.VerifyBufferSignature (buffer, 1024, signature->GetReadPtr (), signature->GetDataAvailableForReading ());
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
    crypto::AsymmetricKey::Ptr key = crypto::HMAC::CreateKey (
        secret.c_str (),
        secret.size ());
    const std::vector<std::string> &messageDigests =
        crypto::CipherSuite::GetMessageDigests ();
    for (std::size_t i = 0, count = messageDigests.size (); i < count; ++i) {
        CHECK_EQUAL (
            TestMAC (
                std::string ("HMAC-" + messageDigests[i]).c_str (),
                key,
                crypto::CipherSuite::GetOpenSSLMessageDigestByName (messageDigests[i])),
            true);
    }
}

TEST (thekogans, CMAC) {
    crypto::OpenSSLInit openSSLInit;
    crypto::AsymmetricKey::Ptr key = crypto::CMAC::CreateKey (
        secret.c_str (),
        secret.size ());
    const std::vector<std::string> &messageDigests =
        crypto::CipherSuite::GetMessageDigests ();
    for (std::size_t i = 0, count = messageDigests.size (); i < count; ++i) {
        CHECK_EQUAL (
            TestMAC (
                std::string ("CMAC-" + messageDigests[i]).c_str (),
                key,
                crypto::CipherSuite::GetOpenSSLMessageDigestByName (messageDigests[i])),
            true);
    }
}

TESTMAIN
