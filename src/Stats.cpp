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

#include "thekogans/crypto/Stats.h"

namespace thekogans {
    namespace crypto {

        void Stats::Update (std::size_t byteCount) {
            ++useCount;
            if (minByteCount > byteCount) {
                minByteCount = byteCount;
            }
            if (maxByteCount < byteCount) {
                maxByteCount = byteCount;
            }
            totalByteCount += byteCount;
        }

        void Stats::Reset () {
            useCount = 0;
            minByteCount = 0;
            maxByteCount = 0;
            totalByteCount = 0;
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const Cipher::Stats::ATTR_USE_COUNT = "UseCount";
        const char * const Cipher::Stats::ATTR_MIN_BYTE_COUNT = "MinByteCount";
        const char * const Cipher::Stats::ATTR_MAX_BYTE_COUNT = "MaxByteCount";
        const char * const Cipher::Stats::ATTR_TOTAL_BYTE_COUNT = "TotalByteCount";

        std::string Stats::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            util::Attributes attributes;
            attributes.push_back (
                util::Attribute (
                    ATTR_USE_COUNT,
                    util::size_tTostring (useCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_MIN_BYTE_COUNT,
                    util::size_tTostring (minByteCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_MAX_BYTE_COUNT,
                    util::size_tTostring (maxByteCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_TOTAL_BYTE_COUNT,
                    util::size_tTostring (totalByteCount)));
            return util::OpenTag (indentationLevel, tagName, attributes, true, true);
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
