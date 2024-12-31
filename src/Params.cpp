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

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_BASE (thekogans::crypto::Params)

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Params::StaticInit () {
            OpenSSLParams::StaticInit ();
            Ed25519Params::StaticInit ();
            X25519Params::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        std::size_t Params::Size () const {
            return Serializable::Size ();
        }

        void Params::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
        }

        void Params::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
        }

        void Params::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            Serializable::Read (header, node);
        }

        void Params::Write (pugi::xml_node &node) const {
            Serializable::Write (node);
        }

        void Params::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            Serializable::Read (header, object);
        }

        void Params::Write (util::JSON::Object &object) const {
            Serializable::Write (object);
        }

    } // namespace crypto
} // namespace thekogans
