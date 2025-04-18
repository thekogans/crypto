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

#if !defined (__thekogans_crypto_X25519AsymmetricKey_h)
#define __thekogans_crypto_X25519AsymmetricKey_h

#include <cstddef>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/FixedArray.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Curve25519.h"

namespace thekogans {
    namespace crypto {

        /// \struct X25519AsymmetricKey X25519AsymmetricKey.h thekogans/crypto/X25519AsymmetricKey.h
        ///
        /// \brief
        /// X25519AsymmetricKey keys are used in ECDHE key exchange (\see{DHEKeyExchange}).

        struct _LIB_THEKOGANS_CRYPTO_DECL X25519AsymmetricKey : public AsymmetricKey {
            /// \brief
            /// X25519AsymmetricKey is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (X25519AsymmetricKey)

            /// \brief
            /// Alias for util::SecureFixedBuffer<X25519::KEY_LENGTH>.
            using KeyType = util::SecureFixedArray<util::ui8, X25519::KEY_LENGTH>;

        private:
            /// \brief
            /// Private/Public \see{X25519} key.
            KeyType key;

            /// \brief
            /// \see{DHEKeyExchange} needs access to key.
            friend struct DHEKeyExchange;

        public:
            /// \brief
            /// ctor.
            /// \param[in] isPrivate true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            X25519AsymmetricKey (
                bool isPrivate = false,
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                AsymmetricKey (isPrivate, id, name, description) {}
            /// \brief
            /// ctor.
            /// \param[in] key_ Private/Public \see{X25519} key.
            /// \param[in] isPrivate true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            X25519AsymmetricKey (
                const util::ui8 *key_,
                bool isPrivate,
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                AsymmetricKey (isPrivate, id, name, description),
                key (key_, X25519::KEY_LENGTH) {}

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
                return X25519::KEY_LENGTH * 8;
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
            /// Read the Serializable from an XML DOM.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void ReadXML (
                const Header &header,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write the Serializable to the XML DOM.
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
            /// X25519AsymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (X25519AsymmetricKey)
        };

        /// \brief
        /// Implement X25519AsymmetricKey extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (X25519AsymmetricKey)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement X25519AsymmetricKey value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::X25519AsymmetricKey)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_X25519AsymmetricKey_h)
