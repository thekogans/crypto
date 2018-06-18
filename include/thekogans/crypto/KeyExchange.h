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

#include <cstddef>
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/SymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyExchange KeyExchange.h thekogans/crypto/KeyExchange.h
        ///
        /// \brief
        /// Base class for computing and exchanging shared \see{SymmetricKey}s.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyExchange : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<KeyExchange>.
            typedef util::ThreadSafeRefCounted::Ptr<KeyExchange> Ptr;

            /// \struct KeyExchange::Params KeyExchange.h thekogans/crypto/KeyExchange.h
            ///
            /// \brief
            /// Key exchange parameters base.
            struct _LIB_THEKOGANS_CRYPTO_DECL Params : public util::Serializable {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Params>.
                typedef util::ThreadSafeRefCounted::Ptr<Params> Ptr;

                /// \brief
                /// KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                ID keyExchangeId;

                /// \brief
                /// ctor.
                /// \param[in] keyExchangeId_ KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                Params (const ID &keyExchangeId_ = ID ()) :
                    keyExchangeId (keyExchangeId_) {}

            protected:
                // util::Serializable
                /// \brief
                /// Return the serializable size.
                /// \return Serializable size.
                virtual std::size_t Size () const;

                /// \brief
                /// Read the serializable from the given serializer.
                /// \param[in] header \see{util::Serializable::Header}.
                /// \param[in] serializer \see{util::Serializer} to read the serializable from.
                virtual void Read (
                    const Header & /*header*/,
                    util::Serializer &serializer);
                /// \brief
                /// Write the serializable to the given serializer.
                /// \param[out] serializer \see{util::Serializer} to write the serializable to.
                virtual void Write (util::Serializer &serializer) const;
            };

        protected:
            /// \brief
            /// KeyExchange id (see \see{KeyRing::AddKeyExchange}).
            ID keyExchangeId;

            /// \brief
            /// \see{KeyRing} needs access to keyExchangeId.
            friend struct KeyRing;

        public:
            /// \brief
            /// ctor.
            /// \param[in] keyExchangeId_ KeyExchange id (see \see{KeyRing::AddKeyExchange}).
            explicit KeyExchange (const ID &keyExchangeId_) :
                keyExchangeId (keyExchangeId_) {}

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \param[in] keyExchangeId KeyExchange id (see \see{KeyRing::AddKeyExchange}).
            /// \return Parameters (\see{DHParams} or \see{RSAParams}) to send to the key exchange peer.
            virtual Params::Ptr GetParams () const = 0;

            /// \brief
            /// Given the peer's (see \see{DHParams} and \see{RSAParams}), use my private key
            /// to derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::Ptr DeriveSharedSymmetricKey (Params::Ptr /*params*/) const = 0;

            /// \brief
            /// KeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (KeyExchange)
        };

        /// \brief
        /// Implement KeyExchange::Params extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (KeyExchange::Params)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyExchange_h)
