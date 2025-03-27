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
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/bcrypt.h"

using namespace thekogans;

namespace {
	const char pass[] = "hi,mom";
	const crypto::bcrypt::HashType hash1 (
        "$2a$10$VEVmGHy4F4XQMJ3eOZJAUeb.MedU0W10pTPCuf53eHdKJPiSE8sMK");
	const crypto::bcrypt::HashType hash2 (
        "$2a$10$3F0BVk5t8/aoS.3ddaB3l.fxg5qvafQ9NybxcpXLzMeAt.nVWn.NO");
}

TEST (thekogans, bcrypt) {
    THEKOGANS_UTIL_TRY {
        crypto::OpenSSLInit openSSLInit;
        {
            std::cout << "bcrypt hash1...";
            crypto::bcrypt::HashType hash = crypto::bcrypt::HashPassword (pass, hash1);
            bool result = std::strcmp (hash, hash1) == 0;
            std::cout << (result ? "pass" : "fail") << std::endl;
            CHECK_EQUAL (result, true);
        }
        {
            std::cout << "bcrypt hash2...";
            crypto::bcrypt::HashType hash = crypto::bcrypt::HashPassword (pass, hash2);
            bool result = std::strcmp (hash, hash2) == 0;
            std::cout << (result ? "pass" : "fail") << std::endl;
            CHECK_EQUAL (result, true);
        }
    }
    THEKOGANS_UTIL_CATCH (util::Exception) {
        std::cout << "fail " << exception.Report ();
        CHECK_EQUAL (false, true);
    }
}

TESTMAIN
