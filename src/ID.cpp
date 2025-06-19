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

#include <cstring>
#include "thekogans/util/SHA2.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        ID::ID (const util::ui8 data_[SIZE]) {
            if (data_ != nullptr) {
                memcpy (data, data_, SIZE);
            }
            else {
                util::SecureZeroMemory (data, SIZE);
            }
        }

        ID ID::FromHexString (const std::string &id) {
            util::ui8 data[SIZE];
            if (!id.empty ()) {
                if (id.size () == SIZE * 2) {
                    if (util::HexDecodestring (id, data) != SIZE) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "%s is not a hex encoded ID.", id.c_str ());
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            else {
                util::SecureZeroMemory (data, SIZE);
            }
            return ID (data);
        }

        ID ID::FromFile (const std::string &path) {
            util::Hash::Digest digest;
            {
                util::SHA2 sha2;
                sha2.FromFile (path, util::SHA2::DIGEST_SIZE_256, digest);
            }
            return ID (digest.data ());
        }

        ID ID::FromBuffer (
                const void *buffer,
                std::size_t length) {
            util::Hash::Digest digest;
            {
                util::SHA2 sha2;
                sha2.FromBuffer (buffer, length, util::SHA2::DIGEST_SIZE_256, digest);
            }
            return ID (digest.data ());
        }

        ID ID::FromRandom (std::size_t length) {
            util::Hash::Digest digest;
            {
                util::SHA2 sha2;
                sha2.FromRandom (length, util::SHA2::DIGEST_SIZE_256, digest);
            }
            return ID (digest.data ());
        }

    } // namespace crypto
} // namespace thekogans
