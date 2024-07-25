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
#include "thekogans/crypto/MessageDigest.h"

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

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyExchange : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (KeyExchange)

            /// \struct KeyExchange::Params KeyExchange.h thekogans/crypto/KeyExchange.h
            ///
            /// \brief
            /// Key exchange parameters base.
            struct _LIB_THEKOGANS_CRYPTO_DECL Params : public util::Serializable {
                /// \brief
                /// Declare \see{RefCounted} pointers.
                THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Params)

                /// \brief
                /// KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                ID id;
                /// \brief
                /// Signature over the parameter data.
                std::vector<util::ui8> signature;
                /// \brief
                /// Signature \see{AsymmetricKey} id.
                ID signatureKeyId;
                /// \brief
                /// OpenSSL message digest to use for parameter hashing.
                std::string signatureMessageDigestName;

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
                /// \param[in] messageDigest Message digest object.
                virtual void CreateSignature (
                    AsymmetricKey::SharedPtr /*privateKey*/,
                    MessageDigest::SharedPtr /*messageDigest*/) = 0;
                /// \brief
                /// Given the peer's public \see{AsymmetricKey}, verify parameters signature.
                /// \param[in] publicKey Peer's public key used to verify parameters signature.
                /// \param[in] messageDigest Message digest object.
                /// \return true == signature is valid, false == signature is invalid.
                virtual bool ValidateSignature (
                    AsymmetricKey::SharedPtr /*publicKey*/,
                    MessageDigest::SharedPtr /*messageDigest*/) = 0;

                // util::Serializable
                /// \brief
                /// Return the serializable size.
                /// \return Serializable size.
                virtual std::size_t Size () const override;

                /// \brief
                /// Read the serializable from the given serializer.
                /// \param[in] header \see{util::Serializable::BinHeader}.
                /// \param[in] serializer \see{util::Serializer} to read the serializable from.
                virtual void Read (
                    const BinHeader & /*header*/,
                    util::Serializer &serializer) override;
                /// \brief
                /// Write the serializable to the given serializer.
                /// \param[out] serializer \see{util::Serializer} to write the serializable to.
                virtual void Write (util::Serializer &serializer) const override;

                /// \brief
                /// "Id"
                static const char * const ATTR_ID;
                /// \brief
                /// "Signature"
                static const char * const ATTR_SIGNATURE;
                /// \brief
                /// "SignatureKeyId"
                static const char * const ATTR_SIGNATURE_KEY_ID;
                /// \brief
                /// "SignatureMessageDigestName"
                static const char * const ATTR_SIGNATURE_MESSAGE_DIGEST_NAME;

                /// \brief
                /// Read the Serializable from an XML DOM.
                /// \param[in] header \see{util::Serializable::TextHeader}.
                /// \param[in] node XML DOM representation of a Serializable.
                virtual void Read (
                    const TextHeader & /*header*/,
                    const pugi::xml_node &node) override;
                /// \brief
                /// Write the Serializable to the XML DOM.
                /// \param[out] node Parent node.
                virtual void Write (pugi::xml_node &node) const override;

                /// \brief
                /// Read a Serializable from an JSON DOM.
                /// \param[in] node JSON DOM representation of a Serializable.
                virtual void Read (
                    const TextHeader & /*header*/,
                    const util::JSON::Object &object) override;
                /// \brief
                /// Write a Serializable to the JSON DOM.
                /// \param[out] node Parent node.
                virtual void Write (util::JSON::Object &object) const override;
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
            /// \param[in] messageDigest Optional message digest object to hash the signature parameters.
            /// \return Parameters (\see{DHEParams} or \see{RSAParams}) to send to the key exchange peer.
            virtual Params::SharedPtr GetParams (
                AsymmetricKey::SharedPtr /*privateKey*/ = AsymmetricKey::SharedPtr (),
                MessageDigest::SharedPtr /*messageDigest*/ = MessageDigest::SharedPtr ()) const = 0;

            /// \brief
            /// Given the peer's (see \see{DHEParams} and \see{RSAParams}), use my private key
            /// to derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::SharedPtr DeriveSharedSymmetricKey (Params::SharedPtr /*params*/) const = 0;

            /// \brief
            /// KeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (KeyExchange)
        };

        /// \brief
        /// Implement KeyExchange::Params::SharedPtr extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_EXTRACTION_OPERATORS (KeyExchange::Params)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement KeyExchange::Params::SharedPtr value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_VALUE_PARSER (crypto::KeyExchange::Params)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyExchange_h)
