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

#include <openssl/evp.h>
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/OpenSSLVerifier.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_RSA)
        THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_DSA)
        THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_EC)

        OpenSSLVerifier::OpenSSLVerifier (
                AsymmetricKey::SharedPtr publicKey,
                MessageDigest::SharedPtr messageDigest) :
                Verifier (publicKey, messageDigest) {
            if (publicKey != nullptr &&
                    !publicKey->IsPrivate () &&
                    (publicKey->GetKeyType () == OPENSSL_PKEY_RSA ||
                        publicKey->GetKeyType () == OPENSSL_PKEY_DSA ||
                        publicKey->GetKeyType () == OPENSSL_PKEY_EC) &&
                    messageDigest != nullptr) {
                if (EVP_DigestVerifyInit (
                        &messageDigest->ctx,
                        0,
                        messageDigest->md,
                        OpenSSLInit::engine,
                        ((OpenSSLAsymmetricKey *)publicKey.Get ())->key.get ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void OpenSSLVerifier::Init () {
            if (EVP_DigestVerifyInit (
                    &messageDigest->ctx,
                    0,
                    messageDigest->md,
                    0,
                    0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void OpenSSLVerifier::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                if (EVP_DigestVerifyUpdate (
                        &messageDigest->ctx,
                        buffer,
                        bufferLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool OpenSSLVerifier::Final (
                const void *signature,
                std::size_t signatureLength) {
            if (signature != 0 && signatureLength > 0) {
                return EVP_DigestVerifyFinal (
                    &messageDigest->ctx,
                    (const util::ui8 *)signature,
                    signatureLength) == 1;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
