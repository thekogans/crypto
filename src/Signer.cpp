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
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/Signer.h"

namespace thekogans {
    namespace crypto {

        Signer::Signer (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_) :
                key (key_),
                md (md_) {
            if (key.Get () != 0 &&
                    (key->GetKeyType () == OPENSSL_PKEY_RSA ||
                        key->GetKeyType () == OPENSSL_PKEY_DSA ||
                        key->GetKeyType () == OPENSSL_PKEY_EC) &&
                    md != 0) {
                if (EVP_DigestSignInit (&ctx, 0, md, OpenSSLInit::engine, (EVP_PKEY *)key->GetKey ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Signer::Init () {
            if (EVP_DigestSignInit (&ctx, 0, md, 0, 0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void Signer::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                if (EVP_DigestSignUpdate (&ctx, buffer, bufferLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Signer::Final (util::ui8 *signature) {
            std::size_t signatureLength = 0;
            if (EVP_DigestSignFinal (&ctx, signature, &signatureLength) == 1) {
                return signatureLength;
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        util::Buffer Signer::Final () {
            std::size_t signatureLength = 0;
            if (EVP_DigestSignFinal (&ctx, 0, &signatureLength) == 1 && signatureLength > 0) {
                util::Buffer signature (util::HostEndian, signatureLength);
                if (EVP_DigestSignFinal (&ctx,
                        signature.GetWritePtr (), &signatureLength) == 1) {
                    signature.AdvanceWriteOffset (signatureLength);
                    return signature;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

    } // namespace crypto
} // namespace thekogans
