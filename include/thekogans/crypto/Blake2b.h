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

#if !defined (__thekogans_crypto_Blake2b_h)
#define __thekogans_crypto_Blake2b_h

#if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)

#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \brief
        /// Object ID for BLAKE2 512 bit.
        extern _LIB_THEKOGANS_CRYPTO_DECL const util::i32 NID_blake2b512;
        /// \brief
        /// Object ID for BLAKE2 384 bit.
        extern _LIB_THEKOGANS_CRYPTO_DECL const util::i32 NID_blake2b384;
        /// \brief
        /// Object ID for BLAKE2 256 bit.
        extern _LIB_THEKOGANS_CRYPTO_DECL const util::i32 NID_blake2b256;

        /// \brief
        /// Return the OpenSSL EVP_MD object representing blake2b 512 bit digest.
        _LIB_THEKOGANS_CRYPTO_DECL const EVP_MD * _LIB_THEKOGANS_CRYPTO_API EVP_blake2b512 ();
        /// \brief
        /// Return the OpenSSL EVP_MD object representing blake2b 384 bit digest.
        _LIB_THEKOGANS_CRYPTO_DECL const EVP_MD * _LIB_THEKOGANS_CRYPTO_API EVP_blake2b384 ();
        /// \brief
        /// Return the OpenSSL EVP_MD object representing blake2b 256 bit digest.
        _LIB_THEKOGANS_CRYPTO_DECL const EVP_MD * _LIB_THEKOGANS_CRYPTO_API EVP_blake2b256 ();

    } // namespace crypto
} // namespace thekogans

#endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)

#endif // !defined (__thekogans_crypto_Blake2b_h)
