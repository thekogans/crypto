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

#if !defined (__thekogans_crypto_CiphertextHeader_h)
#define __thekogans_crypto_CiphertextHeader_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct CiphertextHeader CiphertextHeader.h thekogans/crypto/CiphertextHeader.h
        ///
        /// \brief
        /// CiphertextHeader is used by \see{Cipher} to frame the generated ciphertext.

        struct _LIB_THEKOGANS_CRYPTO_DECL CiphertextHeader {
            /// \brief
            /// Initialization vector (IV) length.
            util::ui16 ivLength;
            /// \brief
            /// Ciphertext length.
            util::ui32 ciphertextLength;
            /// \brief
            /// Message Authentication Code (MAC) length.
            util::ui16 macLength;

            /// \brief
            /// CiphertextHeader serialized size.
            static const std::size_t SIZE =
                util::UI16_SIZE +
                util::UI32_SIZE +
                util::UI16_SIZE;

            /// \brief
            /// ctor.
            CiphertextHeader () :
                ivLength (0),
                ciphertextLength (0),
                macLength (0) {}

            /// \brief
            /// ctor.
            /// \param[in] ivLength_ Initialization vector (IV) length.
            /// \param[in] ciphertextLength_ Ciphertext length.
            /// \param[in] macLength_ Message Authentication Code (MAC) length.
            CiphertextHeader (
                util::ui16 ivLength_,
                util::ui32 ciphertextLength_,
                util::ui16 macLength_) :
                ivLength (ivLength_),
                ciphertextLength (ciphertextLength_),
                macLength (macLength_) {}

            /// \brief
            /// Return the total length of ciphertext represented by this header.
            /// \return Total length of ciphertext represented by this header.
            inline util::ui32 GetTotalLength () const {
                return ivLength + ciphertextLength + macLength;
            }

            /// \brief
            /// Check the validity of this ciphertext header.
            /// \param[in] maxPayloadLength Maximum payload length.
            /// \return true = valid, false = invalid.
            inline bool IsValid (util::ui32 maxPayloadLength) const {
                return ivLength > 0 && ciphertextLength > 0 && macLength > 0 &&
                    GetTotalLength () <= maxPayloadLength;
            }
        };

        /// \brief
        /// CiphertextHeader serializer.
        /// \param[in] serializer Where to serialize the ciphertext header.
        /// \param[in] ciphertextHeader CiphertextHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const CiphertextHeader &ciphertextHeader) {
            serializer <<
                ciphertextHeader.ivLength <<
                ciphertextHeader.ciphertextLength <<
                ciphertextHeader.macLength;
            return serializer;
        }

        /// \brief
        /// CiphertextHeader deserializer.
        /// \param[in] serializer Where to deserialize the ciphertext header.
        /// \param[out] ciphertextHeader CiphertextHeader to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                CiphertextHeader &ciphertextHeader) {
            serializer >>
                ciphertextHeader.ivLength >>
                ciphertextHeader.ciphertextLength >>
                ciphertextHeader.macLength;
            return serializer;
        }

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_CiphertextHeader_h)
