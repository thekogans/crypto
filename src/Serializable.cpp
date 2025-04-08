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

#include "thekogans/util/SpinLock.h"
#include "thekogans/util/LockGuard.h"
#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/crypto/KeyRing.h"
    #include "thekogans/crypto/SymmetricKey.h"
    #include "thekogans/crypto/Params.h"
    #include "thekogans/crypto/KeyExchange.h"
    #include "thekogans/crypto/AsymmetricKey.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/Serializable.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_ABSTRACT_BASE (thekogans::crypto::Serializable)

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Serializable::StaticInit () {
            KeyRing::StaticInit ();
            SymmetricKey::StaticInit ();
            Params::StaticInit ();
            KeyExchange::Params::StaticInit ();
            AsymmetricKey::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        std::size_t Serializable::Size () const noexcept {
            return
                util::Serializer::Size (id) +
                util::Serializer::Size (name) +
                util::Serializer::Size (description);
        }

        void Serializable::Read (
                const Header & /*header*/,
                util::Serializer &serializer) {
            serializer >> id >> name >> description;
        }

        void Serializable::Write (util::Serializer &serializer) const {
            serializer << id << name << description;
        }

        const char * const Serializable::ATTR_ID = "Id";
        const char * const Serializable::ATTR_NAME = "Name";
        const char * const Serializable::ATTR_DESCRIPTION = "Description";

        void Serializable::Read (
                const Header & /*header*/,
                const pugi::xml_node &node) {
            id = ID::FromHexString (node.attribute (ATTR_ID).value ());
            name = node.attribute (ATTR_NAME).value ();
            description = node.attribute (ATTR_DESCRIPTION).value ();
        }

        void Serializable::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_ID).set_value (id.ToHexString ().c_str ());
            node.append_attribute (ATTR_NAME).set_value (name.c_str ());
            node.append_attribute (ATTR_DESCRIPTION).set_value (description.c_str ());
        }

        void Serializable::Read (
                const Header & /*header*/,
                const util::JSON::Object &object) {
            id = ID::FromHexString (object.Get<util::JSON::String> (ATTR_ID)->value);
            name = object.Get<util::JSON::String> (ATTR_NAME)->value;
            description = object.Get<util::JSON::String> (ATTR_DESCRIPTION)->value;
        }

        void Serializable::Write (util::JSON::Object &object) const {
            object.Add<const std::string &> (ATTR_ID, id.ToHexString ());
            object.Add<const std::string &> (ATTR_NAME, name);
            object.Add<const std::string &> (ATTR_DESCRIPTION, description);
        }

    } // namespace crypto
} // namespace thekogans
