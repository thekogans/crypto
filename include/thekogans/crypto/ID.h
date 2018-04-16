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
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct ID ID.h thekogans/crypto/ID.h
        ///
        /// \brief
        /// Ids are randomly generated 32 byte values. They're used by \see{Serializable}.

        struct _LIB_THEKOGANS_CRYPTO_DECL ID {
            /// \enum
            /// ID size.
            enum {
                SIZE = 32
            };
            /// \brief
            /// Key ID.
            util::ui8 data[SIZE];

            /// \brief
            /// ctor.
            ID () {
                if (util::GlobalRandomSource::Instance ().GetBytes (data, SIZE) != SIZE) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get %u random bytes for ID.", SIZE);
                }
            }
            /// \brief
            /// ctor. Initialize to a given value.
            /// \param[in] data_ Value to initialize to.
            explicit ID (const util::ui8 data_[SIZE]) {
                memcpy (data, data_, SIZE);
            }
            /// \brief
            /// ctor.
            /// \param[in] serializer \see{util::Serializer} containing the serialized id.
            explicit ID (util::Serializer &serializer);

            /// \brief
            /// Empty id.
            static const ID Empty;

            /// \brief
            /// Return the id size.
            /// \return ID size.
            inline std::size_t Size () const {
                return SIZE;
            }
            /// \brief
            /// Serialize the id to the given serializer.
            /// \param[out] serializer \see{util::Serializer} serialize the id to.
            void Serialize (util::Serializer &serializer) const;

            /// \brief
            /// Return a hex string representation of the id.
            /// \return Hex string representation of the id.
            inline std::string ToString () const {
                return util::HexEncodeBuffer (data, SIZE);
            }
        };

        /// \brief
        /// Return true if id1 sorts before id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 sorts before id2.
        inline bool operator < (
                const ID &id1,
                const ID &id2) {
            return memcmp (id1.data, id2.data, ID::SIZE) < 0;
        }

        /// \brief
        /// Return true if id1 is equivalent to id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 is equivalent to id2.
        inline bool operator == (
                const ID &id1,
                const ID &id2) {
            return TimeInsensitiveCompare (id1.data, id2.data, ID::SIZE);
        }

        /// \brief
        /// Return true if id1 is not equivalent to id2.
        /// \param[in] id1 First id to compare.
        /// \param[in] id2 Second id to compare.
        /// \return true if id1 is not equivalent to id2.
        inline bool operator != (
                const ID &id1,
                const ID &id2) {
            return !TimeInsensitiveCompare (id1.data, id2.data, ID::SIZE);
        }

        /// \brief
        /// ID serializer.
        /// \param[in] serializer Where to serialize the key id.
        /// \param[in] id ID to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
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
        inline util::Serializer &operator >> (
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

#endif // !defined (__thekogans_crypto_ID_h)
