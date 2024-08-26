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
#include "thekogans/crypto/OpenSSLSigner.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_RSA)
        THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_DSA)
        THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_EC)

        OpenSSLSigner::OpenSSLSigner (
                AsymmetricKey::SharedPtr privateKey,
                MessageDigest::SharedPtr messageDigest) :
                Signer (privateKey, messageDigest) {
            if (privateKey != nullptr &&
                    privateKey->IsPrivate () &&
                    (privateKey->GetKeyType () == OPENSSL_PKEY_RSA ||
                        privateKey->GetKeyType () == OPENSSL_PKEY_DSA ||
                        privateKey->GetKeyType () == OPENSSL_PKEY_EC) &&
                    messageDigest != nullptr) {
                if (EVP_DigestSignInit (
                        &messageDigest->ctx,
                        0,
                        messageDigest->md,
                        OpenSSLInit::engine,
                        ((OpenSSLAsymmetricKey *)privateKey.Get ())->key.get ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void OpenSSLSigner::Init () {
            if (EVP_DigestSignInit (
                    &messageDigest->ctx,
                    0,
                    messageDigest->md,
                    0,
                    0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void OpenSSLSigner::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (EVP_DigestSignUpdate (
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

        std::size_t OpenSSLSigner::Final (util::ui8 *signature) {
            if (signature != nullptr) {
                std::size_t signatureLength = privateKey->GetKeyLength ();
                if (EVP_DigestSignFinal (
                        &messageDigest->ctx,
                        signature,
                        &signatureLength) == 1) {
                    return signatureLength;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
