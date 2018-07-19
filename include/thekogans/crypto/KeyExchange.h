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
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyExchange KeyExchange.h thekogans/crypto/KeyExchange.h
        ///
        /// \brief
        /// Base class for computing and exchanging shared \see{SymmetricKey}s.
        /// VERY, VERY IMPORTANT: KeyExchange is designed for a one-shot use case
        /// and is not reusable. Multiple calls to \see{DeriveSharedSymmetricKey}
        /// will return the same \see{SymmetricKey}. If you need to exchange multiple
        /// keys, you need to instantiate multiple KeyExchange (\see{DHEKeyExchange}
        /// or/and \see{RSAKeyExchange}) instances.

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
                ID id;
                /// \brief
                /// Signature over the parameter data.
                util::Buffer signature;
                /// \brief
                /// Signature \see{AsymmetricKey} id.
                ID signatureKeyId;
                /// \brief
                /// OpenSSL message digest to use for parameter hashing.
                std::string signatureMessageDigest;

                /// \brief
                /// ctor.
                /// \param[in] id_ KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                Params (const ID &id_ = ID ()) :
                    id (id_),
                    signatureKeyId (ID::Empty) {}

                /// \brief
                /// Given my private \see{AsymmetricKey}, create a signature over the parameters.
                /// \param[in] privateKey My private \see{AsymmetricKey} used to create a signature
                /// over the parameters.
                /// \param[in] md OpenSSL message digest used to hash the parameters.
                virtual void CreateSignature (
                    AsymmetricKey::Ptr /*privateKey*/,
                    const EVP_MD * /*md*/) = 0;
                /// \brief
                /// Given the peer's public \see{AsymmetricKey}, verify parameters signature.
                /// \param[in] publicKey Peer's public key used to verify parameters signature.
                /// \param[in] md OpenSSL message digest used to hash the parameters.
                /// \return true == signature is valid, false == signature is invalid.
                virtual bool ValidateSignature (
                    AsymmetricKey::Ptr /*publicKey*/,
                    const EVP_MD * /*md*/) = 0;

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
            ID id;

        public:
            /// \brief
            /// ctor.
            /// \param[in] id_ KeyExchange id (see \see{KeyRing::AddKeyExchange}).
            explicit KeyExchange (const ID &id_) :
                id (id_) {}

            /// \brief
            /// Return the key exchange id.
            /// \return Key exchange id.
            inline const ID &GetId () const {
                return id;
            }

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \param[in] privateKey Optional my private \see{AsymmetricKey} used to create a signature
            /// over the parameters.
            /// \param[in] md Optional OpenSSL message digest used to hash the parameters.
            /// \return Parameters (\see{DHEParams} or \see{RSAParams}) to send to the key exchange peer.
            virtual Params::Ptr GetParams (
                AsymmetricKey::Ptr /*privateKey*/ = AsymmetricKey::Ptr (),
                const EVP_MD * /*md*/ = 0) const = 0;

            /// \brief
            /// Given the peer's (see \see{DHEParams} and \see{RSAParams}), use my private key
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
