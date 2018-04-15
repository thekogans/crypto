// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#if !defined (__thekogans_crypto_DSA_h)
#define __thekogans_crypto_DSA_h

#include <cstddef>
#include <string>
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        /// \struct DSA DSA.h thekogans/crypto/DSA.h
        ///
        /// \brief
        /// Call \see{Params::CreateKey} on parameters created by ParamsFromKeyLength
        /// to create authentication keys to be used with \see{Authenticatior} for sign
        /// and verify operations.

        struct _LIB_THEKOGANS_CRYPTO_DECL DSA {
            /// \brief
            /// Create DSA key parameters.
            /// \param[in] keyLength The length of the key.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return DSA key parameters.
            static Params::Ptr ParamsFromKeyLength (
                std::size_t keyLength,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_DSA_h)
