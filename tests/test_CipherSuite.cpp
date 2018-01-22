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
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/RSA.h"

using namespace thekogans;

namespace {
    bool TestCipherSuite (const crypto::CipherSuite &cipherSuite) {
        std::cout << cipherSuite.ToString () << "...";
        bool result = cipherSuite.IsValid ();
        if (result) {
            result = crypto::CipherSuite (cipherSuite.ToString ()) == cipherSuite;
            if (result) {
                util::Buffer buffer (util::HostEndian, cipherSuite.Size ());
                buffer << cipherSuite;
                crypto::CipherSuite cipherSuite_;
                buffer >> cipherSuite_;
                result = cipherSuite_ == cipherSuite;
                if (result) {
                    crypto::AsymmetricKey::Ptr privateKey = crypto::RSA::CreateKey (512);
                    crypto::KeyExchange::Ptr keyExchange = cipherSuite.GetKeyExchange (privateKey);
                    result = keyExchange.Get () != 0;
                    if (result) {
                        crypto::Authenticator::Ptr authenticator =
                            cipherSuite.GetAuthenticator (crypto::Authenticator::Sign, privateKey);
                        result = authenticator.Get () != 0;
                        if (result) {
                            crypto::Cipher::Ptr cipher = cipherSuite.GetCipher (
                                crypto::SymmetricKey::FromRandom (
                                    crypto::Cipher::GetKeyLength (
                                        cipherSuite.GetOpenSSLCipher (cipherSuite.cipher))));
                            result = cipher.Get () != 0;
                            if (result) {
                                crypto::MessageDigest::Ptr messageDigest = cipherSuite.GetMessageDigest ();
                                result = messageDigest.Get () != 0;
                                if (!result) {
                                    std::cout << "fail messageDigest.Get () == 0" << std::endl;
                                }
                            }
                            else {
                                std::cout << "fail cipher.Get () == 0" << std::endl;
                            }
                        }
                        else {
                            std::cout << "fail authenticator.Get () == 0" << std::endl;
                        }
                    }
                    else {
                        std::cout << "fail keyExchange.Get () == 0" << std::endl;
                    }
                }
                else {
                    std::cout << "fail cipherSuite_ == cipherSuite" << std::endl;
                }
            }
            else {
                std::cout << "fail CipherSuite (cipherSuite.ToString ()) != cipherSuite" << std::endl;
            }
        }
        else {
            std::cout << "fail !cipherSuite.IsValid ()" << std::endl;
        }
        if (result) {
            std::cout << "pass" << std::endl;
        }
        return result;
    }
}

TEST (thekogans, CipherSuite) {
    crypto::OpenSSLInit openSSLInit;
    const std::vector<crypto::CipherSuite> &cipherSuites = crypto::CipherSuite::GetCipherSuites ();
    for (std::size_t i = 0, count = cipherSuites.size (); i < count; ++i) {
        CHECK_EQUAL (TestCipherSuite (cipherSuites[i]), true);
    }
}

TESTMAIN
