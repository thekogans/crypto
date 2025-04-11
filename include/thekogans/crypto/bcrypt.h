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

#if !defined (__thekogans_crypto_bcrypt_h)
#define __thekogans_crypto_bcrypt_h

#include <cstring>
#include "thekogans/util/Exception.h"
#include "thekogans/util/FixedArray.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct bcrypt bcrypt.h thekogans/crypto/bcrypt.h
        ///
        /// \brief
        /// bcrypt is a very thin wrapper around crypt_blowfish from
        /// http://www.openwall.com/crypt/, a secure password hashing
        /// algorithm. Any time you're thinking of storing passwords
        /// in long term storage, think bcrypt. It uses prefix "$2b$".
        ///
        /// Ex:
        ///
        /// Hashing a password:
        ///
        /// \code{.cpp}
        /// using namespace thekogans;
        ///
        /// crypto::bcrypt::HashType hash = crypto::bcrypt::HashPassword ("thepassword");
        /// // You can now store the hash in the database.
        /// \endcode
        ///
        /// Verifying a password:
        ///
        /// \code{.cpp}
        /// using namespace thekogans;
        ///
        /// // Once the users password hash is retrieved
        /// // check if the suplied password matches.
        /// if (crypto::bcrypt::CheckPassword ("thepassword", hash)) {
        ///     // The password matches.
        /// }
        /// else {
        ///     // The password does NOT match.
        /// }
        /// \endcode

        struct _LIB_THEKOGANS_CRYPTO_DECL bcrypt {
            /// \brief
            /// Hash size.
            static const std::size_t HASH_SIZE = 64;
            /// \struct bcrypt::SecureCharArray bcrypt.h thekogans/crypto/bcrypt.h
            ///
            /// \brief
            /// SecureCharArray is a specialization of \see{util::SecureFixedArray}.
            /// Adds extra protection by checking the length of the input.
            struct _LIB_THEKOGANS_CRYPTO_DECL SecureCharArray :
                    public util::SecureFixedArray<char, HASH_SIZE> {
                /// \brief
                /// ctor.
                /// \param[in] array '\0' terminated char string to initialize the array with.
                SecureCharArray (const char *array = nullptr) :
                    util::SecureFixedArray<char, HASH_SIZE> (
                        array, array != nullptr ? std::strlen (array) : 0) {}
            };
            /// \brief
            /// Alias for SecureCharArray.
            using SaltType = SecureCharArray;
            /// \brief
            /// Alias for SecureCharArray.
            using HashType = SecureCharArray;

            /// \brief
            /// Default work factor.
            static const std::size_t DEFAULT_WORK = 12;

            /// \brief
            /// Get a fresh salt vector for password hashing.
            /// \param[in] work A number between 4 and 31 that determines
            /// the amount of work done by HashPassword to twart brute force attacks.
            /// \return A fresh salt vector ready for hashing.
            static SaltType GetSalt (std::size_t work = DEFAULT_WORK);
            /// \brief
            /// Hash the given password with the given salt vector to produce a
            /// password hash ready for long term storage.
            /// \param[in] password Password to hash.
            /// \param[in] salt Salt vector to hash.
            /// \return Hash of password and salt vector.
            static HashType HashPassword (
                const util::SecureString &password,
                const SaltType &salt = GetSalt ());
            /// \brief
            /// Check the given password against the given hash.
            /// \param[in] password Password to check.
            /// \param[in] hash Hash to check.
            /// \return true == password and hash match.
            /// false == password and hash do NOT match.
            static bool CheckPassword (
                const util::SecureString &password,
                const HashType &hash);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_bcrypt_h)
