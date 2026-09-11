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
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/CMAC.h"

namespace thekogans {
    namespace crypto {

        CMAC::CMAC (
                SymmetricKey::SharedPtr key_,
                const EVP_CIPHER *cipher_) :
                key (key_),
                cipher (cipher_),
                ctx (MACContext::TYPE_CMAC) {
            if (key != nullptr && cipher != nullptr) {
                OSSL_PARAM params[2];
                params[0] = OSSL_PARAM_construct_utf8_string (
                    OSSL_MAC_PARAM_CIPHER, const_cast<char *> (EVP_CIPHER_get0_name (cipher)), 0);
                params[1] = OSSL_PARAM_construct_end ();
                if (EVP_MAC_init (
                        &ctx,
                        key->Get (),
                        key->Get ().GetLength (),
                        params) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void CMAC::Init () {
            if (EVP_MAC_init (&ctx, 0, 0, 0) != 1) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void CMAC::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (EVP_MAC_update (&ctx, (const util::ui8 *)buffer, bufferLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t CMAC::Final (util::ui8 *signature) {
            if (signature != nullptr) {
                std::size_t signatureLength = 0;
                if (EVP_MAC_final (
                        &ctx, signature, &signatureLength, EVP_MAX_MD_SIZE) == 1) {
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
            return 0;
        }

    } // namespace crypto
} // namespace thekogans
