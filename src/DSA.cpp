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
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/DSA.h"

namespace thekogans {
    namespace crypto {

        EVP_PKEYPtr DSA::ParamsFromKeyLength (std::size_t keyLength) {
            if (keyLength > 0) {
                EVP_PKEY *params = 0;
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new_id (EVP_PKEY_DSA, OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_paramgen_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_dsa_paramgen_bits (ctx.get (), (util::i32)keyLength) == 1 &&
                        EVP_PKEY_paramgen (ctx.get (), &params) == 1) {
                    return EVP_PKEYPtr (params);
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

        util::Buffer::UniquePtr DSA::SaveParams (EVP_PKEY &params) {
            if (EVP_PKEY_base_id (&params) == EVP_PKEY_DSA) {
                DSAPtr dsaParams (EVP_PKEY_get1_DSA (&params));
                if (dsaParams.get () != 0) {
                    util::i32 parmsLength = i2d_DSAparams (dsaParams.get (), 0);
                    if (parmsLength > 0) {
                        util::Buffer::UniquePtr buffer (
                            new util::Buffer (
                                util::NetworkEndian,
                                util::UI32_SIZE + // MAGIC32
                                util::I32_SIZE + // parmsLength
                                parmsLength)); // params
                        *buffer << util::MAGIC32 << parmsLength;
                        util::ui8 *paramsData = buffer->GetWritePtr ();
                        buffer->AdvanceWriteOffset (
                            (util::ui32)i2d_DSAparams (dsaParams.get (), &paramsData));
                        return buffer;
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
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid parameters type %d.",
                    EVP_PKEY_base_id (&params));
            }
        }

        EVP_PKEYPtr DSA::LoadParams (util::Serializer &serializer) {
            util::ui32 magic;
            serializer >> magic;
            if (magic == util::MAGIC32) {
                util::i32 paramsLength;
                serializer >> paramsLength;
                std::vector<util::ui8> params (paramsLength);
                serializer.Read (&params[0], paramsLength);
                const util::ui8 *paramsData = &params[0];
                DSAPtr dsaParams (d2i_DSAparams (0, &paramsData, paramsLength));
                if (dsaParams.get () != 0) {
                    EVP_PKEYPtr evpParams (EVP_PKEY_new ());
                    if (EVP_PKEY_assign_DSA (evpParams.get (), dsaParams.release ()) == 1) {
                        return evpParams;
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
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid parameters buffer signature %u.",
                    magic);
            }
        }

    } // namespace crypto
} // namespace thekogans
