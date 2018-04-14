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
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/MAC.h"

namespace thekogans {
    namespace crypto {

        MAC::MAC (
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_) :
                key (key_),
                md (md_) {
            if (key.Get () != 0 && md != 0) {
                Init (ctx, key->Get (), md, OpenSSLInit::engine);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void MAC::Init (
                MDContext &ctx,
                EVP_PKEY *key,
                const EVP_MD *md,
                ENGINE *engine) {
            if (EVP_DigestSignInit (&ctx, 0, md, engine, key) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void MAC::Update (
                MDContext &ctx,
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

        std::size_t MAC::Final (
                MDContext &ctx,
                util::ui8 *signature) {
            if (signature != 0) {
                std::size_t signatureLength = 0;
                if (EVP_DigestSignFinal (&ctx, signature, &signatureLength) == 1) {
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

        std::size_t MAC::SignBuffer (
                const void *buffer,
                std::size_t bufferLength,
                util::ui8 *signature) {
            if (buffer != 0 && bufferLength > 0 && signature != 0) {
                Init (ctx, 0, md, 0);
                Update (ctx, buffer, bufferLength);
                return Final (ctx, signature);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr MAC::SignBuffer (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                Init (ctx, 0, md, 0);
                Update (ctx, buffer, bufferLength);
                util::ui8 signature[EVP_MAX_MD_SIZE];
                std::size_t signatureLength = Final (ctx, signature);
                return util::Buffer::UniquePtr (
                    new util::Buffer (
                        util::HostEndian, signature, signature + signatureLength));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool MAC::VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const void *signature,
                std::size_t signatureLength) {
            if (buffer != 0 && bufferLength > 0 &&
                    signature != 0 && signatureLength > 0) {
                Init (ctx, 0, md, 0);
                Update (ctx, buffer, bufferLength);
                util::ui8 computedSignature[EVP_MAX_MD_SIZE];
                std::size_t computedSignatureLength = Final (ctx, computedSignature);
                return signatureLength == computedSignatureLength &&
                    TimeInsensitiveCompare (
                        signature,
                        computedSignature,
                        signatureLength);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
