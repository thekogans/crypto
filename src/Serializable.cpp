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

#include "thekogans/crypto/Serializable.h"

namespace thekogans {
    namespace crypto {

        Serializable::Serializable (util::Serializer &serializer) {
            serializer >> id >> name >> description;
        }

        std::size_t Serializable::Size () const {
            return
                util::Serializer::Size (id) +
                util::Serializer::Size (name) +
                util::Serializer::Size (description);
        }

        void Serializable::Serialize (util::Serializer &serializer) const {
            serializer << id << name << description;
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const Serializable::TAG_SERIALIZABLE = "Serializable";
        const char * const Serializable::ATTR_TYPE = "Type";
        const char * const Serializable::ATTR_ID = "Id";
        const char * const Serializable::ATTR_NAME = "Name";
        const char * const Serializable::ATTR_DESCRIPTION = "Description";
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
