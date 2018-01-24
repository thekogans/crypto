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

#if !defined (__thekogans_crypto_Serializables_h)
#define __thekogans_crypto_Serializables_h

#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct Serializables Serializables.h thekogans/crypto/Serializables.h
        ///
        /// \brief
        /// Used by \see{OpenSSLInit} to register internal serializables
        /// (See \see{KeyRing}, \see{Params}, \see{SymmetricKey} and \see{AsymmetricKey}).

        struct _LIB_THEKOGANS_CRYPTO_DECL Serializables {
        #if defined (TOOLCHAIN_TYPE_Static)
            /// \brief
            /// Register internal serializable types.
            /// NOTE: Because the crypto library uses dynamic initialization,
            /// when using it in static builds OpenSSLInit calls this method
            /// to have the library explicitly include all internal serializable types.
            /// Without calling this api, \see{Serializable::Get} will fail.
            static void StaticInit ();
        #endif // defined (TOOLCHAIN_TYPE_Static)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Serializables_h)
