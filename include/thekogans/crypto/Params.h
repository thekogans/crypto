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
        /// AsymmetricKey is the base for all PKI key parameters. It defines the base API
        /// that all concrete parameters must implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL Params : public Serializable {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Params>.
            typedef util::ThreadSafeRefCounted::Ptr<Params> Ptr;

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
            virtual const char *GetKeyType () const = 0;

            /// \brief
            /// Create an \see{AsymmetricKey} based on parameters.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return \see{AsymmetricKey} based on parameters.
            virtual AsymmetricKey::Ptr CreateKey (
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
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the key from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer);
            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to serialize the key to.
            virtual void Write (util::Serializer &serializer) const;

        public:
            /// \brief
            /// "ParamsType"
            static const char * const ATTR_PARAMS_TYPE;
        };

        /// \brief
        /// Implement Params extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (Params)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Params_h)
