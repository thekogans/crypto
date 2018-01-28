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

#if !defined (__thekogans_crypto_KeyExchange_h)
#define __thekogans_crypto_KeyExchange_h

#include "thekogans/util/RefCounted.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyExchange KeyExchange.h thekogans/crypto/KeyExchange.h
        ///
        /// \brief
        /// A class for computing and exchanging shared \see{SymmetricKey}s.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyExchange : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<KeyExchange>.
            typedef util::ThreadSafeRefCounted::Ptr<KeyExchange> Ptr;

        private:
            /// \brief
            /// Private key used for \see{SymmetricKey} derivation.
            AsymmetricKey::Ptr privateKey;
            /// \brief
            /// OpenSSL key derivation context.
            EVP_PKEY_CTXPtr ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] privateKey Private key used for \see{SymmetricKey} derivation.
            explicit KeyExchange (AsymmetricKey::Ptr privateKey_);

            /// \brief
            /// Call this method to get the public key (your half of the shared secret).
            /// \return The public key.
            inline AsymmetricKey::Ptr GetPublicKey () const {
                return privateKey->GetPublicKey ();
            }

            /// \brief
            /// Given the peer's public key, use my private key to derive the
            /// shared \see{SymmetricKey}.
            /// \param[in] publicKey Peer's public key.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] md OpenSSL message digest to use for the signing operation.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Shared \see{SymmetricKey}.
            SymmetricKey::Ptr DeriveSharedSymmetricKey (
                AsymmetricKey::Ptr publicKey,
                std::size_t keyLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// KeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (KeyExchange)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyExchange_h)
