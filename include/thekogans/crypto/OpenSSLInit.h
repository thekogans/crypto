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

#if !defined (__thekogans_crypto_OpenSSLInit_h)
#define __thekogans_crypto_OpenSSLInit_h

#include <openssl/engine.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLInit OpenSSLInit.h thekogans/crypto/OpenSSLInit.h
        ///
        /// \brief
        /// OpenSSLInit encapsulates the details of initializing the OpenSSL
        /// library. Instantiate one of these before making any calls in to
        /// the library proper.

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLInit {
            /// \brief
            /// OpenSSL engine object used to accelerate cryptographic operations.
            static ENGINE *engine;

            enum {
                /// \brief
                /// Minimum entropy bytes to use for PRNG seeding
                /// (anything less than this would weaken the crypto).
                MIN_ENTROPY_NEEDED = 512,
                /// \brief
                /// Default entropy bytes to use for PRNG seeding.
                DEFAULT_ENTROPY_NEEDED = 1024,
                /// \brief
                /// Default \see{util::SecureAllocator} working set size. thekogans_crypto
                /// uses a lot of secure memory. All \see{SymmetricKey}s, IVs, shared secrets...
                /// are allocated from \see{util::SecureAllocator}. Some OSs (specifically
                /// Windows) severely limit the number of pages that get wired in for any
                /// process. It's important that you pick a working set size appropriate to
                /// your needs.
                DEFAULT_WORKING_SET_SIZE = 1024 * 1024
            };
            /// \brief
            /// ctor.
            /// Initialize the Open SSL library.
            /// \param[in] multiThreaded true = initialize thread support.
            /// \param[in] entropyNeeded Number of entropy bytes to use to seed the PRNG.
            /// \param[in] workingSetSize Physical pages to reserve.
            /// NOTE: All values are in bytes.
            /// \param[in] opensslDir Path to openssl.cnf.
            /// \param[in] engine_ OpenSSL engine object used to accelerate cryptographic operations.
            OpenSSLInit (
                bool multiThreaded = true,
                util::ui32 entropyNeeded = DEFAULT_ENTROPY_NEEDED,
                util::ui64 workingSetSize = DEFAULT_WORKING_SET_SIZE,
                const std::string &opensslDir = std::string (),
                ENGINE *engine_ = 0);
            /// \brief
            /// \dtor.
            virtual ~OpenSSLInit ();

            /// \brief
            /// OpenSSLInit is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (OpenSSLInit)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLInit_h)
