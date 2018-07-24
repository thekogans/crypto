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

#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/Curve25519.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/Ed25519Params.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_ED25519_PARAMS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_ED25519_PARAMS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_ED25519_PARAMS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            Ed25519Params,
            1,
            THEKOGANS_CRYPTO_MIN_ED25519_PARAMS_IN_PAGE)

        AsymmetricKey::Ptr Ed25519Params::CreateKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            util::SecureVector<util::ui8> privateKey (Ed25519::PRIVATE_KEY_LENGTH);
            Ed25519::CreateKey (privateKey.data ());
            return AsymmetricKey::Ptr (
                new Ed25519AsymmetricKey (privateKey.data (), true, id, name, description));
        }

        std::size_t Ed25519Params::Size () const {
            return Serializable::Size ();
        }

        void Ed25519Params::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
        }

        void Ed25519Params::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        std::string Ed25519Params::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PARAMS_TYPE, Ed25519AsymmetricKey::KEY_TYPE));
            return util::OpenTag (indentationLevel, tagName, attributes, true, true);
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
