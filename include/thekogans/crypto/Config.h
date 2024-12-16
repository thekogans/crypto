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

#if !defined (__thekogans_crypto_Config_h)
#define __thekogans_crypto_Config_h

#if !defined (__cplusplus)
    #error libthekogans_crypto requires C++ compilation (use a .cpp suffix)
#endif // !defined (__cplusplus)

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_CRYPTO_API __stdcall
    #if defined (THEKOGANS_CRYPTO_TYPE_Shared)
        #if defined (_LIB_THEKOGANS_CRYPTO_BUILD)
            #define _LIB_THEKOGANS_CRYPTO_DECL __declspec (dllexport)
        #else // defined (_LIB_THEKOGANS_CRYPTO_BUILD)
            #define _LIB_THEKOGANS_CRYPTO_DECL __declspec (dllimport)
        #endif // defined (_LIB_THEKOGANS_CRYPTO_BUILD)
    #else // defined (THEKOGANS_CRYPTO_TYPE_Shared)
        #define _LIB_THEKOGANS_CRYPTO_DECL
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Shared)
    #if defined (_MSC_VER)
        #pragma warning (disable: 4251)  // using non-exported as public in exported
        #pragma warning (disable: 4786)
    #endif // defined (_MSC_VER)
#else // defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_CRYPTO_API
    #define _LIB_THEKOGANS_CRYPTO_DECL
#endif // defined (TOOLCHAIN_OS_Windows)

/// \def THEKOGANS_CRYPTO
/// Logging subsystem name.
#define THEKOGANS_CRYPTO "thekogans_crypto"

/// \def THEKOGANS_CRYPTO_DEFAULT_CIPHER
/// Default cipher.
#define THEKOGANS_CRYPTO_DEFAULT_CIPHER EVP_aes_256_gcm ()
/// \def THEKOGANS_CRYPTO_DEFAULT_MD
/// Default message digest.
#define THEKOGANS_CRYPTO_DEFAULT_MD EVP_sha256 ()

namespace thekogans {
    namespace crypto {

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        /// \brief
        /// If you're linking to thekogans_crypto statically, call this
        /// method early on in main to initialize dynamically creatable
        /// (\see{DynamicCreatable}) types. If you don't call this method
        /// the only available types that will be available to your
        /// application are the ones you explicitly link to.
        void StaticInit ();
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Config_h)
