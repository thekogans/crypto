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

#if !defined (__thekogans_crypto_FrameHeader_h)
#define __thekogans_crypto_FrameHeader_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        /// \struct FrameHeader FrameHeader.h thekogans/crypto/FrameHeader.h
        ///
        /// \brief
        /// FrameHeader serves a dual purpose; 1. FrameHeader implements the packet
        /// framing protocol. Every packet traveling through the wire will be framed
        /// with the information contained in the FrameHeader. This information is
        /// sent in the clear as it defines control necessary to decrypt  the packet.
        /// 2. Data blocks at rest are prefixed by FrameHeader to identify which
        /// \see{Key} from the \see{KeyRing} was used to encrypt which block.

        struct _LIB_THEKOGANS_CRYPTO_DECL FrameHeader {
            /// \brief
            /// \see{SymmetricKey} id used to encrypt this frame.
            ID keyId;
            /// \brief
            /// Length of following ciphertext.
            util::ui32 ciphertextLength;

            enum {
                /// \brief
                /// FrameHeader serialized size.
                SIZE = ID::SIZE + util::UI32_SIZE
            };

            /// \brief
            /// ctor.
            FrameHeader () :
                keyId (ID::Empty),
                ciphertextLength (0) {}

            /// \brief
            /// ctor.
            /// \param[in] keyId_ \see{SymmetricKey} id used to encrypt this frame.
            /// \param[in] ciphertextLength_ Length of following ciphertext.
            FrameHeader (
                const ID &keyId_,
                util::ui32 ciphertextLength_) :
                keyId (keyId_),
                ciphertextLength (ciphertextLength_) {}
        };

        /// \brief
        /// FrameHeader serializer.
        /// \param[in] serializer Where to serialize the frame header.
        /// \param[in] frameHeader FrameHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const FrameHeader &frameHeader) {
            serializer << frameHeader.keyId << frameHeader.ciphertextLength;
            return serializer;
        }

        /// \brief
        /// FrameHeader deserializer.
        /// \param[in] serializer Where to deserialize the frame header.
        /// \param[in] frameHeader FrameHeader to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                FrameHeader &frameHeader) {
            serializer >> frameHeader.keyId >> frameHeader.ciphertextLength;
            return serializer;
        }

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_FrameHeader_h)
