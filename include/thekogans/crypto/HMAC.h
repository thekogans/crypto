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

#if !defined (__thekogans_crypto_HMAC_h)
#define __thekogans_crypto_HMAC_h

#include <openssl/evp.h>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/MAC.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct HMAC HMAC.h thekogans/crypto/HMAC.h
        ///
        /// \brief
        /// Implements the HMAC (Hash-based Message Authentication Code).

        struct _LIB_THEKOGANS_CRYPTO_DECL HMAC : public MAC {
        private:
            /// \brief
            /// Key used in the MAC operation.
            SymmetricKey::SharedPtr key;
            /// \brief
            /// Message digest object.
            const EVP_MD *md;
            /// \brief
            /// OpenSSL HMAC context.
            HMACContext ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ Key used in the MAC operation.
            /// \param[in] md_ OpenSSL message digest object.
            HMAC (
                SymmetricKey::SharedPtr key_,
                const EVP_MD *md_);

            /// \brief
            /// Return the mac key.
            /// \return MAC \see{SymmetricKey}.
            inline SymmetricKey::SharedPtr GetKey () const {
                return key;
            }
            /// \brief
            /// Return the OpenSSL message digest object.
            /// \return OpenSSL message digest object.
            inline const EVP_MD *GetMD () const {
                return md;
            }

            /// \brief
            /// Return the length of the mac.
            /// \return Length of the mac.
            virtual std::size_t GetMACLength () const override {
                return GetMDLength (md);
            }

            /// \brief
            /// Initialize the context (ctx) and get it ready for MAC generation.
            virtual void Init () override;
            /// \brief
            /// Call this method 1 or more times to generate a MAC.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void *buffer,
                std::size_t bufferLength) override;
            /// \brief
            /// Finalize the MAC and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 *signature) override;
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_HMAC_h)
