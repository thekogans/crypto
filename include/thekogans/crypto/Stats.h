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

#if !defined (__thekogans_crypto_Stats_h)
#define __thekogans_crypto_Stats_h

#include <string>
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/Types.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct Stats Stats.h thekogans/crypto/Stats.h
        ///
        /// \brief
        /// Keeps track of usage statistics for various key components.

        struct _LIB_THEKOGANS_CRYPTO_DECL Stats {
            /// \brief
            /// Number of times this component was used.
            std::size_t useCount;
            /// \brief
            /// The shortest buffer this component saw.
            std::size_t minByteCount;
            /// \brief
            /// The longest buffer this component saw.
            std::size_t maxByteCount;
            /// \brief
            /// Total bytes processed by this component.
            std::size_t totalByteCount;

            /// \brief
            /// ctor.
            Stats () :
                useCount (0),
                minByteCount (0),
                maxByteCount (0),
                totalByteCount (0) {}

            /// \brief
            /// Update the usage statistics.
            /// \param[in] byteCount Current buffer length.
            void Update (std::size_t byteCount);

            /// \brief
            /// Reset the stats to 0.
            void Reset ();

        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// "UseCount"
            static const char * const ATTR_USE_COUNT;
            /// \brief
            /// "MinByteCount"
            static const char * const ATTR_MIN_BYTE_COUNT;
            /// \brief
            /// "MaxByteCount"
            static const char * const ATTR_MAX_BYTE_COUNT;
            /// \brief
            /// "TotalByteCount"
            static const char * const ATTR_TOTAL_BYTE_COUNT;

            /// \brief
            /// Return the XML representation of stats.
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of stats.
            std::string ToString (
                util::ui32 indentationLevel,
                const char *tagName) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Stats_h)
