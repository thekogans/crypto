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

#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/MAC.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct CMAC CMAC.h thekogans/crypto/CMAC.h
        ///
        /// \brief
        /// Implements the CMAC (Cipher-based Message Authentication Code).

        struct _LIB_THEKOGANS_CRYPTO_DECL CMAC : public MAC {
        private:
            /// \brief
            /// Key used in the MAC operation.
            SymmetricKey::Ptr key;
            /// \brief
            /// OpenSSL cipher object.
            const EVP_CIPHER *cipher;
            /// \brief
            /// OpenSSL CMAC context.
            CMACContext ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ Key used in the MAC operation.
            /// \param[in] cipher_ OpenSSL cipher object.
            CMAC (
                SymmetricKey::Ptr key_,
                const EVP_CIPHER *cipher_);

            /// \brief
            /// Return the mac key.
            /// \return MAC \see{SymmetricKey}.
            inline SymmetricKey::Ptr GetKey () const {
                return key;
            }
            /// \brief
            /// Return the OpenSSL cipher object.
            /// \return OpenSSL cipher object.
            inline const EVP_CIPHER *GetCipher () const {
                return cipher;
            }

            /// \brief
            /// Return the length of the mac.
            /// \return Length of the mac.
            virtual std::size_t GetMACLength () const {
                return EVP_CIPHER_block_size (cipher);
            }

            /// \brief
            /// Initialize the context (ctx) and get it ready for MAC generation.
            virtual void Init ();
            /// \brief
            /// Call this method 1 or more times to generate a MAC.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Finalize the MAC and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 *signature);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_CMAC_h)
