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
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"

using namespace thekogans;

TEST (thekogans, SymmetricKey) {
    crypto::OpenSSLInit openSSLInit;
    CHECK_EQUAL (true, true);
}

TEST (thekogans, AsymmetricKey) {
    crypto::OpenSSLInit openSSLInit;
    CHECK_EQUAL (true, true);
}

TESTMAIN
