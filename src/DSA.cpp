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
#include <openssl/dsa.h>
#include "thekogans/crypto/OpenSSLParams.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/DSA.h"

namespace thekogans {
    namespace crypto {

        Params::SharedPtr DSA::ParamsFromKeyLength (
                std::size_t keyLength,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (keyLength > 0) {
                EVP_PKEY *params = 0;
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new_id (EVP_PKEY_DSA, OpenSSLInit::engine));
                if (ctx != nullptr &&
                        EVP_PKEY_paramgen_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_dsa_paramgen_bits (ctx.get (), (util::i32)keyLength) == 1 &&
                        EVP_PKEY_paramgen (ctx.get (), &params) == 1) {
                    return Params::SharedPtr (new OpenSSLParams (EVP_PKEYPtr (params), id, name, description));
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
