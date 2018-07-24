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

#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        std::size_t AsymmetricKey::Size () const {
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

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const AsymmetricKey::ATTR_PRIVATE = "Private";
        const char * const AsymmetricKey::ATTR_KEY_TYPE = "KeyType";
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
