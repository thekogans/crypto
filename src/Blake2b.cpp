// Copyright 2016 Boris Kogan (boris@thekogans.net)
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

#if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)

#include <cstring>
#include <blake2.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "thekogans/crypto/Blake2b.h"

namespace thekogans {
    namespace crypto {

        namespace {
            int init (EVP_MD_CTX *ctx) {
                blake2b_param P;
                P.digest_length = EVP_MD_CTX_size (ctx);
                P.key_length = 0;
                P.fanout = 1;
                P.depth = 1;
                P.leaf_length = 0;
                P.node_offset = 0;
                P.xof_length = 0;
                P.node_depth    = 0;
                P.inner_length  = 0;
                memset (P.reserved, 0, sizeof (P.reserved));
                memset (P.salt, 0, sizeof (P.salt));
                memset (P.personal, 0, sizeof (P.personal));
                blake2b_init_param ((blake2b_state *)ctx->md_data, &P);
                return 1;
            }

            int update (
                    EVP_MD_CTX *ctx,
                    const void *data,
                    size_t count) {
                return blake2b_update ((blake2b_state *)ctx->md_data, data, count) == 0 ? 1 : 0;
            }

            int final (
                    EVP_MD_CTX *ctx,
                    unsigned char *md) {
                return blake2b_final ((blake2b_state *)ctx->md_data, md, EVP_MD_CTX_size (ctx)) == 0 ? 1 : 0;
            }
        }

        const EVP_MD *EVP_blake2b512 () {
            static const EVP_MD blake2b512 = {
                OBJ_create ("", "blake2b512", "blake2b512"),
                0,
                64,
                0,
                init,
                update,
                final,
                0,
                0,
                0,
                0,
                {0, 0, 0, 0, 0},
                BLAKE2B_BLOCKBYTES,
                sizeof (blake2bp_state),
                0
            };
            return &blake2b512;
        }

        const EVP_MD *EVP_blake2b384 () {
            static const EVP_MD blake2b384 = {
                OBJ_create ("", "blake2b384", "blake2b384"),
                0,
                48,
                0,
                init,
                update,
                final,
                0,
                0,
                0,
                0,
                {0, 0, 0, 0, 0},
                BLAKE2B_BLOCKBYTES,
                sizeof (blake2bp_state),
                0
            };
            return &blake2b384;
        }

        const EVP_MD *EVP_blake2b256 () {
            static const EVP_MD blake2b256 = {
                OBJ_create ("", "blake2b256", "blake2b256"),
                0,
                32,
                0,
                init,
                update,
                final,
                0,
                0,
                0,
                0,
                {0, 0, 0, 0, 0},
                BLAKE2B_BLOCKBYTES,
                sizeof (blake2bp_state),
                0
            };
            return &blake2b256;
        }

    } // namespace crypto
} // namespace thekogans

#endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
