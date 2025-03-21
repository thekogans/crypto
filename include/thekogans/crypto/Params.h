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

#if !defined (__thekogans_crypto_Params_h)
#define __thekogans_crypto_Params_h

#include <string>
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        /// \struct Params Params.h thekogans/crypto/Params.h
        ///
        /// \brief
        /// Params is the base for all PKI key parameters. It defines the base API
        /// that all concrete parameters must implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL Params : public Serializable {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE_BASE (Params)

        #if defined (THEKOGANS_CRYPTO_TYPE_Static)
            static void StaticInit ();
        #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

            /// \brief
            /// ctor.
            /// \param[in] id Optional parameters id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            Params (
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Serializable (id, name, description) {}

            /// \brief
            /// Return the key type.
            /// \return Key type.
            virtual std::string GetKeyType () const = 0;

            /// \brief
            /// Create an \see{AsymmetricKey} based on parameters.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return \see{AsymmetricKey} based on parameters.
            virtual AsymmetricKey::SharedPtr CreateKey (
                const ID & /*id*/ = ID (),
                const std::string & /*name*/ = std::string (),
                const std::string & /*description*/ = std::string ()) const = 0;

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
            /// Read the Serializable from an XML DOM.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const Header &header,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write the Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const Header &header,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;
        };

        /// \brief
        /// Implement Params::SharedPtr extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (Params)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement Params::SharedPtr value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::Params)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Params_h)
