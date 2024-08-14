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

#include <string>
#include <iostream>
#include <CppUnitXLite/CppUnitXLite.cpp>
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/Cipher.h"

using namespace thekogans;

namespace {
    const std::string password ("password");
    const std::string message ("The quick brown fox jumped over the lazy dog.");
    const std::string associatedData ("The dog barks at night.");

    bool TestCipher (
            const char *name,
            crypto::Cipher &cipher,
            const void *plaintext,
            std::size_t plaintextLength,
            const void *associatedData = 0,
            std::size_t associatedDataLength = 0) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            util::Buffer::SharedPtr ciphertext = cipher.Encrypt (
                plaintext,
                plaintextLength,
                associatedData,
                associatedDataLength);
            util::Buffer::SharedPtr decryptedPlaintext = cipher.Decrypt (
                ciphertext->GetReadPtr (),
                ciphertext->GetDataAvailableForReading (),
                associatedData,
                associatedDataLength);
            bool result = message ==
                std::string (
                    (const char *)plaintext,
                    (const char *)plaintext + plaintextLength);
                std::string (
                    decryptedPlaintext->GetReadPtr (),
                    decryptedPlaintext->GetReadPtrEnd ());
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }
}

TEST (thekogans, CBC) {
    crypto::OpenSSLInit openSSLInit;
    crypto::Cipher cipher (
        crypto::SymmetricKey::FromSecretAndSalt (
            password.c_str (),
            password.size (),
            0,
            0,
            crypto::GetCipherKeyLength (EVP_aes_256_cbc ())),
        EVP_aes_256_gcm ());
    CHECK_EQUAL (
        TestCipher (
            "CBC",
            cipher,
            message.c_str (),
            message.size ()),
        true);
}

TEST (thekogans, GCM) {
    crypto::OpenSSLInit openSSLInit;
    crypto::Cipher cipher (
        crypto::SymmetricKey::FromSecretAndSalt (
            password.c_str (),
            password.size (),
            0,
            0,
            crypto::GetCipherKeyLength ()));
    CHECK_EQUAL (
        TestCipher (
            "GCM",
            cipher,
            message.c_str (),
            message.size (),
            associatedData.c_str (),
            associatedData.size ()),
        true);
}

TESTMAIN
