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

#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/MessageDigest.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        namespace {
            const util::ui8 _data_[ID::SIZE] = {
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX
            };
        }

        const ID ID::Empty (_data_);

        namespace {
            void HashBuffer (
                    const void *buffer,
                    std::size_t length,
                    util::ui8 *hash) {
                MessageDigest messageDigest (EVP_sha256 ());
                messageDigest.Init ();
                messageDigest.Update (buffer, length);
                length = messageDigest.Final (hash);
                if (length != ID::SIZE) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Incorrect ID length (%u, %u).", length, ID::SIZE);
                }
            }
        }

        ID::ID (const void *buffer,
                std::size_t length) {
            if (buffer != 0 && length > 0) {
                HashBuffer (buffer, length, data);
            }
            else if (util::GlobalRandomSource::Instance ().GetBytes (data, SIZE) != SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to get %u random bytes for ID.", SIZE);
            }
        }

        ID::ID (const std::string &id) {
            HashBuffer (id.c_str (), id.size (), data);
        }

        ID::ID (util::Serializer &serializer) {
            if (serializer.Read (data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to read %u bytes from the buffer.", ID::SIZE);
            }
        }

        void ID::Serialize (util::Serializer &serializer) const {
            if (serializer.Write (data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to write %u bytes to the buffer.", ID::SIZE);
            }
        }

    } // namespace crypto
} // namespace thekogans
