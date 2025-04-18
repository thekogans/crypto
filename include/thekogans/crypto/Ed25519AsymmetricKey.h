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

#if !defined (__thekogans_crypto_Ed25519AsymmetricKey_h)
#define __thekogans_crypto_Ed25519AsymmetricKey_h

#include <cstddef>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Curve25519.h"

namespace thekogans {
    namespace crypto {

        /// \struct Ed25519AsymmetricKey Ed25519AsymmetricKey.h thekogans/crypto/Ed25519AsymmetricKey.h
        ///
        /// \brief
        /// Ed25519AsymmetricKey keys are used to perform sign/verify
        /// operations (\see{Authenticator}).

        struct _LIB_THEKOGANS_CRYPTO_DECL Ed25519AsymmetricKey : public AsymmetricKey {
            /// \brief
            /// Ed25519AsymmetricKey is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (Ed25519AsymmetricKey)

        private:
            /// \brief
            /// \see{Ed25519} Private/Public keys.
            union {
                /// \brief
                /// Private \see{Ed25519} key.
                util::ui8 privateKey[Ed25519::PRIVATE_KEY_LENGTH];
                struct {
                    /// \brief
                    /// Shift the location of the public key to align with where it is in the
                    /// private key representation.
                    util::ui8 pad[Ed25519::PRIVATE_KEY_LENGTH - Ed25519::PUBLIC_KEY_LENGTH];
                    /// \brief
                    /// Public \see{Ed25519} key.
                    util::ui8 value[Ed25519::PUBLIC_KEY_LENGTH];
                } publicKey;
            } key;

            /// \brief
            /// \see{Ed25519Signer} needs access to key.
            friend struct Ed25519Signer;
            /// \brief
            /// \see{Ed25519Verifier} needs access to key.
            friend struct Ed25519Verifier;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ \see{Ed25519} Private/Public keys.
            /// \param[in] isPrivate true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            Ed25519AsymmetricKey (
                const util::ui8 *key_ = 0,
                bool isPrivate = false,
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            ~Ed25519AsymmetricKey () {
                util::SecureZeroMemory (key.privateKey, Ed25519::PRIVATE_KEY_LENGTH);
            }

            /// \brief
            /// "KeyType"
            static const char * const KEY_TYPE;

            /// \brief
            /// Return the key type.
            /// \return Key type.
            virtual std::string GetKeyType () const override {
                return KEY_TYPE;
            }

            /// \brief
            /// Return the key length (in bits).
            /// \return Key length (in bits).
            virtual std::size_t GetKeyLength () const override {
                return (IsPrivate () ? Ed25519::PRIVATE_KEY_LENGTH : Ed25519::PUBLIC_KEY_LENGTH) * 8;
            }

            /// \brief
            /// Return the public key associated with this private key.
            /// If this is a public key only, return a duplicate.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public part of the privateKey (or duplicate of the pubilc key).
            virtual AsymmetricKey::SharedPtr GetPublicKey (
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const override;

            // Serializable
            /// \brief
            /// Return the serialized key size.
            /// \return Serialized key size.
            virtual std::size_t Size () const noexcept override;

            /// \brief
            /// Read the key from the given serializer.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the key from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer) override;
            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to serialize the key to.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// "Key"
            static const char * const ATTR_KEY;

            /// \brief
            /// Read a Serializable from an XML DOM.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void ReadXML (
                const Header &header,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write a Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void WriteXML (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void ReadJSON (
                const Header &header,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void WriteJSON (util::JSON::Object &object) const override;

            /// \brief
            /// Ed25519AsymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (Ed25519AsymmetricKey)
        };

        /// \brief
        /// Implement Ed25519AsymmetricKey extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (Ed25519AsymmetricKey)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement Ed25519AsymmetricKey value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::Ed25519AsymmetricKey)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Ed25519AsymmetricKey_h)
