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

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE (
            thekogans::crypto::OpenSSLSigner,
            Signer::TYPE)

        OpenSSLSigner::OpenSSLSigner (
                AsymmetricKey::SharedPtr privateKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (privateKey_ != nullptr && messageDigest_ != nullptr) {
                Init (privateKey_, messageDigest_);
            }
        }

        bool OpenSSLSigner::HasKeyType (const std::string &keyType) {
            return
                keyType == OPENSSL_PKEY_RSA ||
                keyType == OPENSSL_PKEY_DSA ||
                keyType == OPENSSL_PKEY_EC;
        }

        void OpenSSLSigner::Init (
                AsymmetricKey::SharedPtr privateKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (privateKey_ != nullptr && messageDigest_ != nullptr) {
                OpenSSLAsymmetricKey::SharedPtr key = privateKey_;
                if (key != nullptr && key->IsPrivate ()) {
                    if (EVP_DigestSignInit (
                            &messageDigest_->ctx,
                            0,
                            messageDigest_->md,
                            OpenSSLInit::engine,
                            key->key.get ()) == 1) {
                        privateKey = privateKey_;
                        messageDigest = messageDigest_;
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
            else if (privateKey != nullptr && messageDigest != nullptr) {
                if (EVP_DigestSignInit (
                        &messageDigest->ctx,
                        0,
                        messageDigest->md,
                        0,
                        0) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "OpenSSLSigner is not initialized.");
            }
        }

        void OpenSSLSigner::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (privateKey != nullptr && messageDigest != nullptr) {
                    if (EVP_DigestSignUpdate (
                            &messageDigest->ctx,
                            buffer,
                            bufferLength) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "OpenSSLSigner is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t OpenSSLSigner::Final (util::ui8 *signature) {
            if (signature != nullptr) {
                if (privateKey != nullptr && messageDigest != nullptr) {
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
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "OpenSSLSigner is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
