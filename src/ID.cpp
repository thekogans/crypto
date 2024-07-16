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
            const util::ui8 emptyIdData[ID::SIZE] = {
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX,
                util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX, util::UI8_MAX
            };
        }

        const ID ID::Empty (emptyIdData);

        ID::ID () {
            if (util::GlobalRandomSource::Instance ()->GetBytes (data, SIZE) != SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to get " THEKOGANS_UTIL_SIZE_T_FORMAT " random bytes for ID.", SIZE);
            }
        }

        ID::ID (const void *buffer,
                std::size_t length) {
            if (buffer != 0 && length > 0) {
                MessageDigest messageDigest (EVP_sha256 ());
                messageDigest.Init ();
                messageDigest.Update (buffer, length);
                length = messageDigest.Final (data);
                if (length != ID::SIZE) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Incorrect ID length (" THEKOGANS_UTIL_SIZE_T_FORMAT ", "
                        THEKOGANS_UTIL_SIZE_T_FORMAT ").",
                        length, ID::SIZE);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        ID::ID (util::Serializer &serializer) {
            if (serializer.Read (data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to read " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes from the buffer.", ID::SIZE);
            }
        }

        void ID::Serialize (util::Serializer &serializer) const {
            if (serializer.Write (data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to write " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes to the buffer.", ID::SIZE);
            }
        }

        ID ID::FromHexString (const std::string &hexString) {
            if (hexString.size () == SIZE * 2) {
                util::ui8 data[SIZE];
                if (util::HexDecodestring (hexString, data) == SIZE) {
                    return ID (data);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s is not a hex encoded ID.", hexString.c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
