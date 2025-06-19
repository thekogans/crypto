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

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <cstring>
#include <blake2.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/Blake2s.h"

namespace thekogans {
    namespace crypto {

        // https://tools.ietf.org/html/draft-saarinen-blake2-03#section-4
        _LIB_THEKOGANS_CRYPTO_DECL const util::i32 NID_blake2s256 = OBJ_create (
            "1.3.6.1.4.1.1722.12.2.2.32",
            "BLAKE2 Cryptographic Hash and MAC (256 bit)",
            "blake2s256");

        namespace {
            void *EVP_MD_CTX_md_data (const EVP_MD_CTX *ctx) {
                return ctx->md_data;
            }

            int init (EVP_MD_CTX *ctx) {
                blake2s_param P;
                P.digest_length = EVP_MD_CTX_size (ctx);
                P.key_length = 0;
                P.fanout = 1;
                P.depth = 1;
                P.leaf_length = 0;
                P.node_offset = 0;
                P.xof_length = 0;
                P.node_depth = 0;
                P.inner_length = 0;
                util::SecureZeroMemory (P.salt, sizeof (P.salt));
                util::SecureZeroMemory (P.personal, sizeof (P.personal));
                blake2s_init_param ((blake2s_state *)EVP_MD_CTX_md_data (ctx), &P);
                return 1;
            }

            int update (
                    EVP_MD_CTX *ctx,
                    const void *data,
                    size_t count) {
                return blake2s_update (
                    (blake2s_state *)EVP_MD_CTX_md_data (ctx),
                    data,
                    count) == 0 ? 1 : 0;
            }

            int final (
                    EVP_MD_CTX *ctx,
                    unsigned char *md) {
                return blake2s_final (
                    (blake2s_state *)EVP_MD_CTX_md_data (ctx),
                    md,
                    EVP_MD_CTX_size (ctx)) == 0 ? 1 : 0;
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL const EVP_MD * _LIB_THEKOGANS_CRYPTO_API EVP_blake2s256 () {
            static const EVP_MD blake2s256 = {
                NID_blake2s256,
                NID_undef,
                32,
                0,
                init,
                update,
                final,
                0,
                0,
                0,
                0,
                {NID_undef, NID_undef, 0, 0, 0},
                BLAKE2S_BLOCKBYTES,
                sizeof (blake2sp_state),
                0
            };
            return &blake2s256;
        }

    } // namespace crypto
} // namespace thekogans

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L

#endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
