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

#if !defined (__thekogans_crypto_AsymmetricKey_h)
#define __thekogans_crypto_AsymmetricKey_h

#include <cstddef>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct AsymmetricKey AsymmetricKey.h thekogans/crypto/AsymmetricKey.h
        ///
        /// \brief
        /// AsymmetricKey is the base for all PKI keys. It defines the base API
        /// that all concrete keys must implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL AsymmetricKey : public Serializable {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<AsymmetricKey>.
            typedef util::ThreadSafeRefCounted::Ptr<AsymmetricKey> Ptr;

        private:
            /// \brief
            /// true = contains both private and public keys.
            /// false = contains only the public key.
            bool isPrivate;

        public:
            /// \brief
            /// ctor.
            /// \param[in] isPrivate_ true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            AsymmetricKey (
                bool isPrivate_ = false,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Serializable (id, name, description),
                isPrivate (isPrivate_) {}

            /// \brief
            /// Return true if it's a private key.
            /// \return true if it's a private key.
            inline bool IsPrivate () const {
                return isPrivate;
            }

            /// \brief
            /// Return the key type.
            /// \return Key type.
            virtual const char *GetKeyType () const = 0;

            /// \brief
            /// Return the key length (in bits).
            /// \return Key length (in bits).
            virtual std::size_t GetKeyLength () const = 0;

            /// \brief
            /// Return the public key associated with this private key.
            /// If this is a public key only, return a duplicate.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public part of the private key (or duplicate of the pubilc key).
            virtual Ptr GetPublicKey (
                const ID & /*id*/ = ID (),
                const std::string & /*name*/ = std::string (),
                const std::string & /*description*/ = std::string ()) const = 0;

        protected:
            // Serializable
            /// \brief
            /// Return the serialized key size.
            /// \return Serialized key size.
            virtual std::size_t Size () const;

            /// \brief
            /// Read the key from the given serializer.
            /// \param[in] header \see{util::Serializable::BinHeader}.
            /// \param[in] serializer \see{util::Serializer} to read the key from.
            virtual void Read (
                const BinHeader &header,
                util::Serializer &serializer);
            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to serialize the key to.
            virtual void Write (util::Serializer &serializer) const;

            /// \brief
            /// "Private"
            static const char * const ATTR_PRIVATE;

            /// \brief
            /// Read the Serializable from an XML DOM.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader &header,
                const pugi::xml_node &node);
            /// \brief
            /// Write the Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader &header,
                const util::JSON::Object &object);
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const;
        };

        /// \brief
        /// Implement AsymmetricKey::Ptr extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_EXTRACTION_OPERATORS (AsymmetricKey)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement AsymmetricKey::Ptr value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_VALUE_PARSER (crypto::AsymmetricKey)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_AsymmetricKey_h)
