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
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/CMAC.h"

namespace thekogans {
    namespace crypto {

        CMAC::CMAC (
                SymmetricKey::Ptr key_,
                const EVP_CIPHER *cipher_) :
                key (key_),
                cipher (cipher_) {
            if (key.Get () != 0 && cipher != 0) {
                if (CMAC_Init (
                        &ctx,
                        key->Get ().GetReadPtr (),
                        key->Get ().GetDataAvailableForReading (),
                        cipher,
                        OpenSSLInit::engine) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void CMAC::Init () {
            if (CMAC_Init (&ctx, 0, 0, 0, 0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void CMAC::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                if (CMAC_Update (&ctx, buffer, bufferLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t CMAC::Final (util::ui8 *signature) {
            if (signature != 0) {
                std::size_t signatureLength = 0;
                if (CMAC_Final (&ctx, signature, &signatureLength) == 1) {
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
