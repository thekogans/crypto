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

#include "thekogans/util/StringUtils.h"
#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/crypto/OpenSSLAsymmetricKey.h"
    #include "thekogans/crypto/Ed25519AsymmetricKey.h"
    #include "thekogans/crypto/X25519AsymmetricKey.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_BASE (thekogans::crypto::AsymmetricKey)

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void AsymmetricKey::StaticInit () {
            OpenSSLAsymmetricKey::StaticInit ();
            Ed25519AsymmetricKey::StaticInit ();
            X25519AsymmetricKey::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        std::size_t AsymmetricKey::Size () const noexcept {
            return
                Serializable::Size () +
                util::Serializer::Size (isPrivate);
        }

        void AsymmetricKey::Read (
                const Header &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
            serializer >> isPrivate;
        }

        void AsymmetricKey::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
            serializer << isPrivate;
        }

        const char * const AsymmetricKey::ATTR_PRIVATE = "Private";

        void AsymmetricKey::Read (
                const Header &header,
                const pugi::xml_node &node) {
            Serializable::Read (header, node);
            isPrivate = util::stringTobool (node.attribute (ATTR_PRIVATE).value ());
        }

        void AsymmetricKey::Write (pugi::xml_node &node) const {
            Serializable::Write (node);
            node.append_attribute (ATTR_PRIVATE).set_value (
                util::boolTostring (IsPrivate ()).c_str ());
        }

        void AsymmetricKey::Read (
                const Header &header,
                const util::JSON::Object &object) {
            Serializable::Read (header, object);
            isPrivate = object.Get<util::JSON::Bool> (ATTR_PRIVATE)->value;
        }

        void AsymmetricKey::Write (util::JSON::Object &object) const {
            Serializable::Write (object);
            object.Add (ATTR_PRIVATE, IsPrivate ());
        }

    } // namespace crypto
} // namespace thekogans
