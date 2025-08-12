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

#if !defined (__thekogans_crypto_X25519Params_h)
#define __thekogans_crypto_X25519Params_h

#include <cstddef>
#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/X25519AsymmetricKey.h"
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        /// \struct X25519Params X25519Params.h thekogans/crypto/X25519Params.h
        ///
        /// \brief
        /// X25519Params are used to create \see{X25519AsymmetricKey} used in
        /// ECDHE key exchange (See \see{DHEKeyExchange}).

        struct _LIB_THEKOGANS_CRYPTO_DECL X25519Params : public Params {
            /// \brief
            /// X25519Params is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (X25519Params)

            /// \brief
            /// ctor.
            /// \param[in] id Optional parameters id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            X25519Params (
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Params (id, name, description) {}

            /// \brief
            /// Return the key type.
            /// \return Key type.
            virtual std::string GetKeyType () const override {
                return X25519AsymmetricKey::KEY_TYPE;
            }

            /// \brief
            /// Create an \see{AsymmetricKey} based on parameters.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return \see{AsymmetricKey} based on parameters.
            virtual AsymmetricKey::SharedPtr CreateKey (
                const ID &id = ID::FromRandom (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const override;

            // Serializable
            /// \brief
            /// Return the serialized params size.
            /// \return Serialized params size.
            virtual std::size_t Size () const noexcept override;

            /// \brief
            /// Read the parameters from the given serializer.
            /// \param[in] header \see{util::SerializableHeader}.
            /// \param[in] serializer \see{util::Serializer} to read the parameters from.
            virtual void Read (
                const util::SerializableHeader &header,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the parameters to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the parameters to.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// Read the Serializable from an XML DOM.
            /// \param[in] header \see{util::SerializableHeader}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void ReadXML (
                const util::SerializableHeader &header,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write the Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void WriteXML (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] header \see{util::SerializableHeader}.
            /// \param[in] object JSON DOM representation of a Serializable.
            virtual void ReadJSON (
                const util::SerializableHeader &header,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] object Parent \see{util::JSON::Object}.
            virtual void WriteJSON (util::JSON::Object &object) const override;

            /// \brief
            /// X25519Params is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (X25519Params)
        };

        /// \brief
        /// Implement X25519Params extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (X25519Params)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement X25519Params value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::X25519Params)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_X25519Params_h)
