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

#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/Verifier.h"

namespace thekogans {
    namespace crypto {

        Verifier::Verifier (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_) :
                key (key_),
                md (md_) {
            if (key.Get () != 0 &&
                    (key->GetKeyType () == OPENSSL_PKEY_RSA ||
                        key->GetKeyType () == OPENSSL_PKEY_DSA ||
                        key->GetKeyType () == OPENSSL_PKEY_EC) &&
                    md != 0) {
                if (EVP_DigestVerifyInit (&ctx, 0, md, OpenSSLInit::engine, (EVP_PKEY *)key->GetKey ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Verifier::Init () {
            if (EVP_DigestVerifyInit (&ctx, 0, md, 0, 0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void Verifier::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                if (EVP_DigestVerifyUpdate (&ctx, buffer, bufferLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Verifier::Final (
                const void *signature,
                std::size_t signatureLength) {
            if (signature != 0 && signatureLength > 0) {
                return EVP_DigestVerifyFinal (&ctx,
                    (const util::ui8 *)signature, signatureLength) == 1;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
