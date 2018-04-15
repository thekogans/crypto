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

#if !defined (__thekogans_crypto_CMAC_h)
#define __thekogans_crypto_CMAC_h

#include <cstddef>
#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct CMAC CMAC.h thekogans/crypto/CMAC.h
        ///
        /// \brief
        /// Pass CMAC keys to \see{MAC} to create Message Authentication Codes (MACs)
        /// over ciphertext. See \see{Cipher} for more information.

        struct _LIB_THEKOGANS_CRYPTO_DECL CMAC {
            /// \brief
            /// Create an CMAC key for signing and verifying.
            /// \param[in] secret Secret to derive key from.
            /// \param[in] secretLength Secret length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] cipher OpenSSL cipher to use for the signing operation.
            /// NOTE: By definition the cupher has to be in CBC mode.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new CMAC key.
            static AsymmetricKey::Ptr CreateKey (
                const void *secret,
                std::size_t secretLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                const EVP_CIPHER *cipher = EVP_aes_256_cbc (),
                std::size_t count = 1,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_CMAC_h)
