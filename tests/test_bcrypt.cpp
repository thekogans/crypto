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
	const char pass[] = "foobar";
	const crypto::bcrypt::HashType hash1 (
        "$2b$12$2QuAjLghBZ2SBpiGgqV2/OCPABhxYElb3KJ11gWlQj62SqCQ1zuSi");
	const crypto::bcrypt::HashType hash2 (
        "$2b$12$y844nkr5lTf5KCSj1xCbDemY3DGJy.9bT3ahzK8GBydLeys0HqK/y");
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
        {
            std::cout << "bcrypt check hash1...";
            bool result = crypto::bcrypt::CheckPassword (pass, hash1);
            std::cout << (result ? "pass" : "fail") << std::endl;
            CHECK_EQUAL (result, true);
        }
        {
            std::cout << "bcrypt check hash2...";
            bool result = crypto::bcrypt::CheckPassword (pass, hash2);
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
