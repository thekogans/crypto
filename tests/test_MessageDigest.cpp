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

#include <cstring>
#include <iostream>
#include <CppUnitXLite/CppUnitXLite.cpp>
#include "thekogans/util/Buffer.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/MessageDigest.h"

using namespace thekogans;

namespace {
    std::string message ("The quck brown fox jumped over the lazy dog.");

    bool TestMessageDigest (
            const char *name,
            const EVP_MD *md) {
        THEKOGANS_UTIL_TRY {
            std::cout << name << "...";
            crypto::MessageDigest messageDigest (md);
            util::Buffer::SharedPtr buffer1 =
                messageDigest.HashBuffer (message.c_str (), message.size ());
            util::Buffer::SharedPtr buffer2 =
                messageDigest.HashBuffer (message.c_str (), message.size ());
            bool result = buffer1->GetDataAvailableForReading () ==
                buffer2->GetDataAvailableForReading () &&
                memcmp (
                    buffer1->GetReadPtr (),
                    buffer2->GetReadPtr (),
                    buffer1->GetDataAvailableForReading ()) == 0;
            if (result) {
                std::string path = name + std::string (".test");
                {
                    util::SimpleFile file (
                        util::NetworkEndian,
                        path,
                        util::SimpleFile::ReadWrite |
                        util::SimpleFile::Create |
                        util::SimpleFile::Truncate);
                    file.Write (message.c_str (), message.size ());
                }
                util::Buffer::SharedPtr buffer1 = messageDigest.HashFile (path);
                util::Buffer::SharedPtr buffer2 = messageDigest.HashFile (path);
                util::File::Delete (path.c_str ());
                result = buffer1->GetDataAvailableForReading () ==
                    buffer2->GetDataAvailableForReading () &&
                    memcmp (
                        buffer1->GetReadPtr (),
                        buffer2->GetReadPtr (),
                        buffer1->GetDataAvailableForReading ()) == 0;
            }
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }
}

TEST (thekogans, MessageDigest) {
    crypto::OpenSSLInit openSSLInit;
    const std::vector<std::string> &messageDigests =
        crypto::CipherSuite::GetMessageDigests ();
    for (std::size_t i = 0, count = messageDigests.size (); i < count; ++i) {
        CHECK_EQUAL (
            TestMessageDigest (
                messageDigests[i].c_str (),
                crypto::CipherSuite::GetOpenSSLMessageDigestByName (messageDigests[i])),
            true);
    }
}

TESTMAIN
