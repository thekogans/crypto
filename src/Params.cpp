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

#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        std::size_t Params::Size () const {
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

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const Params::ATTR_PARAMS_TYPE = "ParamsType";
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
