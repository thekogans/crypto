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

#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/crypto/OpenSSLParams.h"
    #include "thekogans/crypto/Ed25519Params.h"
    #include "thekogans/crypto/X25519Params.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_ABSTRACT_BASE (thekogans::crypto::Params)

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Params::StaticInit () {
            OpenSSLParams::StaticInit ();
            Ed25519Params::StaticInit ();
            X25519Params::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        std::size_t Params::Size () const noexcept {
            return Serializable::Size ();
        }

        void Params::Read (
                const Header &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
        }

        void Params::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
        }

        void Params::ReadXML (
                const Header &header,
                const pugi::xml_node &node) {
            Serializable::ReadXML (header, node);
        }

        void Params::WriteXML (pugi::xml_node &node) const {
            Serializable::WriteXML (node);
        }

        void Params::ReadJSON (
                const Header &header,
                const util::JSON::Object &object) {
            Serializable::ReadJSON (header, object);
        }

        void Params::WriteJSON (util::JSON::Object &object) const {
            Serializable::WriteJSON (object);
        }

    } // namespace crypto
} // namespace thekogans
