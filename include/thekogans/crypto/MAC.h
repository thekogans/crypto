// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#if !defined (__thekogans_crypto_MAC_h)
#define __thekogans_crypto_MAC_h

#include <cstddef>
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct MAC MAC.h thekogans/crypto/MAC.h
        ///
        /// \brief
        /// MAC is a base class for \see{HMAC} and \see{CMAC}. It
        /// implements Message Authentication Codes for \see{Cipher}.
        /// NOTE: You can call SignBuffer and VerifyBufferSignature as
        /// many times as you need and in any order. MAC is designed to
        /// be reused. It will reset it's internal state after every
        /// sign/verify operation ready for the next.

        struct _LIB_THEKOGANS_CRYPTO_DECL MAC : public virtual util::RefCounted {
            /// \brief
            /// Convenient typedef for util::RefCounted::SharedPtr<MAC>.
            typedef util::RefCounted::SharedPtr<MAC> SharedPtr;

            /// \brief
            /// dtor.
            virtual ~MAC () {}

            /// \brief
            /// Return the length of the mac.
            /// \return Length of the mac.
            virtual std::size_t GetMACLength () const = 0;

            /// \brief
            /// Initialize the context (ctx) and get it ready for MAC generation.
            virtual void Init () = 0;
            /// \brief
            /// Call this method 1 or more times to generate a MAC.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void * /*buffer*/,
                std::size_t /*bufferLength*/) = 0;
            /// \brief
            /// Finalize the MAC and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 * /*signature*/) = 0;

            /// \brief
            /// Used by \see{Cipher} to MAC in place saving an allocation
            /// and a copy, improving performance.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            std::size_t SignBuffer (
                const void *buffer,
                std::size_t bufferLength,
                util::ui8 *signature);
            /// \brief
            /// Create a buffer signature (MAC).
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            /// \return Buffer signature.
            util::Buffer SignBuffer (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Verify the given buffer signature (MAC).
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            /// \param[in] signature Signature to verify.
            /// \param[in] signatureLength Signature length.
            /// \return true == valid, false == invalid.
            bool VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const void *signature,
                std::size_t signatureLength);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_MAC_h)
