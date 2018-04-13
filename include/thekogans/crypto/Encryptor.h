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

#if !defined (__thekogans_crypto_Encryptor_h)
#define __thekogans_crypto_Encryptor_h

#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Stats.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct Encryptor Encryptor.h thekogans/crypto/Encryptor.h
        ///
        /// \brief
        /// Encryptor implements stream based symmetric encryption using AES (CBC or GCM mode).

        struct _LIB_THEKOGANS_CRYPTO_DECL Encryptor {
        private:
            /// \brief
            /// Cipher context used during encryption.
            CipherContext context;
            /// \brief
            /// Encryptor stats.
            Stats stats;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key SymmetricKey used for encryption.
            /// \param[in] cipher Cipher used for encryption.
            Encryptor (
                const SymmetricKey &key,
                const EVP_CIPHER *cipher);

            /// \brief
            /// Return the length of the initialization vector (IV) associated with the cipher.
            /// \return The length of the initialization vector (IV) associated with the cipher.
            inline std::size_t GetIVLength () const {
                return EVP_CIPHER_CTX_iv_length (&context);
            }
            /// \brief
            /// Generate a random iv.
            /// \param[out] iv Where to place the generated iv.
            /// \return Number of bytes written to iv.
            std::size_t GetIV (util::ui8 *iv) const;

            /// \brief
            /// Set the initialization vector (IV).
            /// \param[in] iv Initialization vector used for encryption.
            void SetIV (const util::ui8 *iv);
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
            /// Call this method 1 or more times to encrypt plaintext.
            /// \param[in] plaintext Buffer containing plaintext.
            /// \param[in] plaintextLength Plaintext buffer length.
            /// \param[out] ciphertext Where to write the ciphertext.
            /// \return Count of bytest written to ciphertext.
            std::size_t Update (
                const void *plaintext,
                std::size_t plaintextLength,
                util::ui8 *ciphertext);
            /// \brief
            /// Call this method to finalize encryption.
            /// \param[out] ciphertext Where to write the ciphertext.
            /// \return Count of bytest written to ciphertext.
            std::size_t Final (util::ui8 *ciphertext);
            /// \brief
            /// In GCM mode the cipher creates the mac for us. After
            /// calling Final, call this method to get the mac (tag
            /// in GCM parlance).
            /// \param[out] tag Where to write the tag.
            /// \return Size of tag (in bytes).
            std::size_t GetTag (util::ui8 *tag);

            /// \brief
            /// Return the reference to stats.
            /// \return Reference to stats.
            inline const Stats &GetStats () const {
                return stats;
            }

            /// \brief
            /// Encryptor is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Encryptor)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Encryptor_h)
