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

#if !defined (__thekogans_crypto_ID_h)
#define __thekogans_crypto_ID_h

#include <cstddef>
#include <cstring>
#include "thekogans/util/Types.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/SHA2.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct ID ID.h thekogans/crypto/ID.h
        ///
        /// \brief
        /// Ids are randomly generated 32 byte values. They're used by \see{Serializable}.

        struct _LIB_THEKOGANS_CRYPTO_DECL ID {
            /// \brief
            /// ID size.
            static const std::size_t SIZE = util::SHA2::DIGEST_SIZE_256;

            /// \brief
            /// \see{Serializable} ID.
            util::ui8 data[SIZE];

            /// \brief
            /// ctor. Initialize to a given value.
            /// \param[in] data_ Value to initialize to.
            /// If nullptr, initialize to all 0.
            ID (const util::ui8 data_[SIZE] = nullptr);

            /// \brief
            /// Return the id size.
            /// \return ID size.
            inline constexpr std::size_t Size () const {
                return SIZE;
            }

            /// \brief
            /// Return a hex string representation of the id.
            /// \return Hex string representation of the id.
            inline std::string ToHexString (bool upperCase = false) const {
                return util::HexEncodeBuffer (data, SIZE, upperCase);
            }

            /// \brief
            /// Parse id from a hex string encoding.
            /// \param[in] id Hex string encoding of an ID.
            /// \return ID.
            static ID FromHexString (const std::string &id);
            /// \brief
            /// Create an id for a given file. Uses \see{util::SHA2::FromFile}.
            /// \param[in] path file to create an id from (SHA2 hash).
            /// \return SHA2 hash of the file.
            static ID FromFile (const std::string &path);
            /// \brief
            /// Create a id for a given buffer. Uses \see{SHA2::FromBuffer}.
            /// \param[in] buffer Pointer to the beginning of the buffer.
            /// \param[in] length Length of the buffer.
            /// \return SHA2 hash of the buffer.
            static ID FromBuffer (
                const void *buffer,
                std::size_t length);
            /// \brief
            /// Create a random id. Uses \see{SHA2::FromRandom}.
            /// \param[in] length Length of random bytes.
            /// \return SHA2 hash of the random bytes.
            static ID FromRandom (std::size_t length = SIZE);
        };

        /// \brief
        /// Return true if id1 sorts before id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 sorts before id2.
        inline bool _LIB_THEKOGANS_CRYPTO_API operator < (
                const ID &id1,
                const ID &id2) {
            return memcmp (id1.data, id2.data, ID::SIZE) < 0;
        }

        /// \brief
        /// Return true if id1 sorts after id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 sorts after id2.
        inline bool _LIB_THEKOGANS_CRYPTO_API operator > (
                const ID &id1,
                const ID &id2) {
            return memcmp (id1.data, id2.data, ID::SIZE) > 0;
        }

        /// \brief
        /// Return true if id1 is equivalent to id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 is equivalent to id2.
        inline bool _LIB_THEKOGANS_CRYPTO_API operator == (
                const ID &id1,
                const ID &id2) {
            return TimeInsensitiveCompare (id1.data, id2.data, ID::SIZE);
        }

        /// \brief
        /// Return true if id1 is not equivalent to id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 is not equivalent to id2.
        inline bool _LIB_THEKOGANS_CRYPTO_API operator != (
                const ID &id1,
                const ID &id2) {
            return !TimeInsensitiveCompare (id1.data, id2.data, ID::SIZE);
        }

        /// \brief
        /// ID serializer.
        /// \param[in] serializer Where to serialize the key id.
        /// \param[in] id ID to serialize.
        /// \return serializer.
        inline util::Serializer & _LIB_THEKOGANS_CRYPTO_API operator << (
                util::Serializer &serializer,
                const ID &id) {
            if (serializer.Write (id.data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to write %u bytes to the serializer.", ID::SIZE);
            }
            return serializer;
        }

        /// \brief
        /// ID deserializer.
        /// \param[in] serializer Where to deserialize the key id.
        /// \param[out] id ID to deserialize.
        /// \return serializer.
        inline util::Serializer & _LIB_THEKOGANS_CRYPTO_API operator >> (
                util::Serializer &serializer,
                ID &id) {
            if (serializer.Read (id.data, ID::SIZE) != ID::SIZE) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to read %u bytes from the serializer.", ID::SIZE);
            }
            return serializer;
        }

    } // namespace crypto
} // namespace thekogans

namespace std {

    /// \struct hash<thekogans::crypto::ID> ID.h thekogans/crypto/ID.h
    ///
    /// \brief
    /// Implementation of std::hash for thekogans::crypto::ID.

    template <>
    struct hash<thekogans::crypto::ID> {
        size_t operator () (const thekogans::crypto::ID &id) const {
            return thekogans::util::HashBuffer32 (
                (const thekogans::util::ui32 *)id.data,
                thekogans::crypto::ID::SIZE >> 2);
        }
    };

} // namespace std

#endif // !defined (__thekogans_crypto_ID_h)
