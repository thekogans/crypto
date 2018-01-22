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

#if !defined (__thekogans_crypto_MessageDigest_h)
#define __thekogans_crypto_MessageDigest_h

#include <string>
#include <openssl/evp.h>
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct MessageDigest MessageDigest.h thekogans/crypto/MessageDigest.h
        ///
        /// \brief
        /// MessageDigest is a convenient interface for creating buffer and file hashes.
        /// It hides the OpenSSL details behind a simple single call interface.
        /// NOTE: You can call Hash[Buffer | File] as many times as you need and in
        /// any order. MessageDigest is designed to be reused. It will reset it's
        /// internal state after every sign/verify operation ready for the next.

        struct _LIB_THEKOGANS_CRYPTO_DECL MessageDigest : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<MessageDigest>.
            typedef util::ThreadSafeRefCounted::Ptr<MessageDigest> Ptr;

        private:
            /// \brief
            /// OpenSSL message digest object.
            const EVP_MD *md;
            /// \brief
            /// EVP_MD_CTX wrapper.
            MDContext ctx;

        public:
            /// \brief
            /// ctor.
            /// \param[in] md_ OpenSSL message digest to use.
            MessageDigest (const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD);

            /// \brief
            /// Create a buffer hash (MessageDigest).
            /// \param[in] buffer Buffer whose hash to create.
            /// \param[in] bufferLength Buffer length.
            /// \return Buffer hash.
            util::Buffer::UniquePtr HashBuffer (
                const void *buffer,
                std::size_t bufferLength);
            /// \brief
            /// Create a file hash (MessageDigest).
            /// \param[in] path File whose hash to create.
            /// \return File hash.
            util::Buffer::UniquePtr HashFile (const std::string &path);

            /// \brief
            /// MessageDigest is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (MessageDigest)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_MessageDigest_h)
