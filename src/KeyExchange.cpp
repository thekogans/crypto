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

#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/KeyExchange.h"

namespace thekogans {
    namespace crypto {

        KeyExchange::KeyExchange (AsymmetricKey::Ptr privateKey_) :
                privateKey (privateKey_) {
            if (privateKey.Get () != 0) {
                ctx.reset (EVP_PKEY_CTX_new (privateKey->Get (), OpenSSLInit::engine));
                if (ctx.get () == 0) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr KeyExchange::DeriveSharedSymmetricKey (
                AsymmetricKey::Ptr publicKey,
                std::size_t keyLength,
                const void *salt,
                std::size_t saltLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (publicKey.Get () != 0 && keyLength > 0 && md != 0) {
                std::size_t secretLength = 0;
                if (EVP_PKEY_derive_init (ctx.get ()) == 1 &&
                        EVP_PKEY_derive_set_peer (ctx.get (), publicKey->Get ()) == 1 &&
                        EVP_PKEY_derive (ctx.get (), 0, &secretLength) == 1) {
                    util::SecureVector<util::ui8> secret (secretLength);
                    if (EVP_PKEY_derive (ctx.get (), &secret[0], &secretLength) == 1) {
                        return SymmetricKey::FromSecretAndSalt (
                            &secret[0],
                            secretLength,
                            salt,
                            saltLength,
                            keyLength,
                            md,
                            count,
                            id,
                            name,
                            description);
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
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
