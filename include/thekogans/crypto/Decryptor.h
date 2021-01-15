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

#if !defined (__thekogans_crypto_Decryptor_h)
#define __thekogans_crypto_Decryptor_h

#include <cstddef>
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Stats.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct Decryptor Decryptor.h thekogans/crypto/Decryptor.h
        ///
        /// \brief
        /// Decryptor implements symmetric decryption using AES (CBC or GCM mode).
        /// NOTE: Decryptor implements a low level API and is exposed in case you
        /// need to decrypt multiple disjoint buffers. That said, there are a lot
        /// of pitfalls to using it (no \see{MAC} validation...). You are strongly
        /// encouraged to use \see{Cipher} as it uses best industry practices. At
        /// the very least you should consult \see{Cipher::Decrypt} to make sure
        /// your code is secure.

        struct _LIB_THEKOGANS_CRYPTO_DECL Decryptor {
        private:
            /// \brief
            /// Cipher context used during decryption.
            CipherContext context;
            /// \brief
            /// Decryptor stats.
            Stats stats;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key SymmetricKey used for decryption.
            /// \param[in] cipher Cipher used for decryption.
            Decryptor (
                SymmetricKey::SharedPtr key,
                const EVP_CIPHER *cipher = THEKOGANS_CRYPTO_DEFAULT_CIPHER);

            /// \brief
            /// Return max buffer length needed to decrypt the given amount of ciphertext.
            /// \param[in] ciphertextLength Amount of ciphertext to decrypt.
            /// \return Max buffer length needed to decrypt the given amount of ciphertext.
            static std::size_t GetMaxBufferLength (std::size_t ciphertextLength) {
                return ciphertextLength;
            }

            /// \brief
            /// Set the initialization vector (IV) and initialize the decryptor.
            /// \param[in] iv Initialization vector used for decryption.
            void Init (const util::ui8 *iv);
            /// \brief
            /// In GCM mode, call this method 0 or more times to set the
            /// associated data.
            /// VERY IMPORTANT: This method must be called before the first call to Update.
            /// \param[in] associatedData Buffer containing associated data.
            /// \param[in] associatedDataLength Associated data buffer length.
            void SetAssociatedData (
                const void *associatedData,
                std::size_t associatedDataLength);
            /// \brief
            /// Call this method 1 or more times to decrypt ciphertext.
            /// \param[in] ciphertext Buffer containing ciphertext.
            /// \param[in] ciphertextLength Ciphertext buffer length.
            /// \param[out] ciphertext Where to write the plaintext.
            /// \return Count of bytest written to plaintext.
            std::size_t Update (
                const void *ciphertext,
                std::size_t ciphertextLength,
                util::ui8 *plaintext);
            /// \brief
            /// In GCM mode the cipher needs the tag (Encryptor::GetTag).
            /// \param[in] tag Buffer containing the tag.
            /// \param[in] tagLength Length of buffer containing the tag.
            /// \return true.
            bool SetTag (
                const void *tag,
                std::size_t tagLength);
            /// \brief
            /// Call this method to finalize decryption.
            /// \param[out] plaintext Where to write the plaintext.
            /// \return Count of bytest written to plaintext.
            std::size_t Final (util::ui8 *plaintext);

            /// \brief
            /// Return the reference to stats.
            /// \return Reference to stats.
            inline const Stats &GetStats () const {
                return stats;
            }

            /// \brief
            /// Decryptor is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Decryptor)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Decryptor_h)
