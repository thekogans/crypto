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
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/CMAC.h"

namespace thekogans {
    namespace crypto {

        AsymmetricKey::Ptr CMAC::CreateKey (
                const void *secret,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                const EVP_CIPHER *cipher,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (secret != 0 && secretLength > 0 &&
                    GetCipherMode (cipher) == EVP_CIPH_CBC_MODE) {
                SymmetricKey::Ptr symmetricKey = SymmetricKey::FromSecretAndSalt (
                    GetCipherKeyLength (cipher),
                    secret,
                    secretLength,
                    salt,
                    saltLength,
                    THEKOGANS_CRYPTO_DEFAULT_MD,
                    count,
                    id,
                    name,
                    description);
                EVP_PKEY *key = 0;
                EVP_PKEY_CTXPtr ctx (EVP_PKEY_CTX_new_id (EVP_PKEY_CMAC, OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_ctrl (ctx.get (), -1, EVP_PKEY_OP_KEYGEN,
                            EVP_PKEY_CTRL_CIPHER, 0, (void *)cipher) == 1 &&
                        EVP_PKEY_CTX_ctrl (ctx.get (), -1, EVP_PKEY_OP_KEYGEN,
                            EVP_PKEY_CTRL_SET_MAC_KEY,
                            (util::i32)symmetricKey->Get ().GetDataAvailableForReading (),
                            (void *)symmetricKey->Get ().GetReadPtr ()) == 1 &&
                        EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                    return AsymmetricKey::Ptr (
                        new AsymmetricKey (EVP_PKEYPtr (key), true, id, name, description));
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
