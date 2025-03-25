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

#include "crypt_blowfish/crypt_blowfish.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/bcrypt.h"

namespace thekogans {
    namespace crypto {

        bcrypt::SaltType bcrypt::GetSalt (std::size_t work) {
            static const std::size_t RANDOM_SIZE = 16;
            util::SecureString random ('\0', RANDOM_SIZE);
            if (util::RandomSource::Instance ()->GetSeedOrBytes (
                    random.data (), random.size ()) == random.size ()) {
                SaltType salt;
                if (_crypt_gensalt_blowfish_rn (
                        "$2b$",
                        (int)((work > 3 && work < 32) ? work : 12),
                        random.data (),
                        (int)random.size (),
                        salt,
                        (int)salt.Size ()) != nullptr) {
                    return salt;
                }
                else{
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to generate salt for work %d.",
                        work);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to get " THEKOGANS_UTIL_UI64_FORMAT " random bytes for salt.",
                    RANDOM_SIZE);
            }
        }

        bcrypt::HashType bcrypt::HashPassword (
                const util::SecureString &password,
                const SaltType &salt) {
            bcrypt::HashType hash;
            if (_crypt_blowfish_rn (
                    password.c_str (),
                    salt,
                    hash,
                    (int)hash.Size ()) != nullptr) {
                return hash;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "Unable to generate password hash.");
            }
        }

        bool bcrypt::CheckPassword (
                const util::SecureString &password,
                const HashType &hash) {
            return TimeInsensitiveCompare (
                hash, HashPassword (password, hash), hash.Size ());
        }

    } // namespace crypto
} // namespace thekogans
