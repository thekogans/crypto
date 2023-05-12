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

#if !defined (__thekogans_crypto_Cipher_h)
#define __thekogans_crypto_Cipher_h

#include <cstddef>
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/Encryptor.h"
#include "thekogans/crypto/Decryptor.h"
#include "thekogans/crypto/MAC.h"
#include "thekogans/crypto/CiphertextHeader.h"
#include "thekogans/crypto/FrameHeader.h"

namespace thekogans {
    namespace crypto {

        /// \struct Cipher Cipher.h thekogans/crypto/Cipher.h
        ///
        /// \brief
        /// Cipher implements symmetric encryption/decryption using AES (CBC or GCM mode)
        /// Every encryption operation uses a random iv to thwart BEAST. MACs (CBC mode)
        /// are calculated over ciphertext to avoid the Cryptographic Doom Principle:
        /// https://moxie.org/blog/the-cryptographic-doom-principle/. See the description
        /// of Cipher::Encrypt for more information.

        struct _LIB_THEKOGANS_CRYPTO_DECL Cipher : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Cipher)

        private:
            /// \brief
            /// \see{SymmetricKey} used to encrypt/decrypt.
            SymmetricKey::SharedPtr key;
            /// \brief
            /// OpenSSL cipher object.
            const EVP_CIPHER *cipher;
            /// \brief
            /// OpenSSL message digest object.
            const EVP_MD *md;
            /// \brief
            /// Encapsulates the encryption operation.
            Encryptor encryptor;
            /// \brief
            /// Encapsulates the decryption operation.
            Decryptor decryptor;
            /// \brief
            /// \see{MAC} used to sign ciphertext in CBC mode.
            MAC::SharedPtr mac;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ \see{SymmetricKey} used to encrypt/decrypt.
            /// \param[in] cipher_ OpenSSL EVP_CIPHER.
            /// \param[in] md_ OpenSSL EVP_MD (CBC mode only, ignored in GCM mode).
            Cipher (
                SymmetricKey::SharedPtr key_,
                const EVP_CIPHER *cipher_ = THEKOGANS_CRYPTO_DEFAULT_CIPHER,
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD);

            enum {
                /// \brief
                /// Maximum framing overhead length.
                MAX_FRAMING_OVERHEAD_LENGTH =
                    FrameHeader::SIZE +
                    CiphertextHeader::SIZE +
                    EVP_MAX_IV_LENGTH + // iv
                    EVP_MAX_BLOCK_LENGTH + // padding
                    EVP_MAX_MD_SIZE, // mac
                /// \brief
                /// Maximum plaintext length.
                MAX_PLAINTEXT_LENGTH =
                    util::UI32_MAX -
                    MAX_FRAMING_OVERHEAD_LENGTH
            };

            /// \brief
            /// Return the max plaintext length that will fit in to the given payload length.
            /// \param[in] payloadLength Max payload length.
            /// \return Max plaintext length that will fit.
            static std::size_t GetMaxPlaintextLength (std::size_t payloadLength);

            /// \brief
            /// Return max buffer length needed to encrypt the given amount of plaintext.
            /// \param[in] plaintextLength Amount of plaintext to encrypt.
            /// \return Max buffer length needed to encrypt the given amount of plaintext.
            static std::size_t GetMaxBufferLength (std::size_t plaintextLength);

            /// \brief
            /// Return the cipher key.
            /// \return Cipher \see{SymmetricKey}.
            inline SymmetricKey::SharedPtr GetKey () const {
                return key;
            }

            /// \brief
            /// Return the encryptor stats.
            /// \return Encryptor stats.
            inline const Stats &GetEncryptorStats () const {
                return encryptor.GetStats ();
            }

            /// \brief
            /// Return the decryptor stats.
            /// \return Decryptor stats.
            inline const Stats &GetDecryptorStats () const {
                return decryptor.GetStats ();
            }

            /// \brief
            /// Encrypt and mac plaintext. This is the workhorse encryption function
            /// used by others below. It writes the following structure in to ciphertext:
            ///
            /// |---------- \see{CiphertextHeader} ----------|--------- ciphertext ---------|
            /// +-----------+-------------------+------------+------+---------------+-------+
            /// | iv length | ciphertext length | mac length |  iv  |  ciphertext   |  mac  |
            /// +-----------+-------------------+------------+------+---------------+-------+
            /// |     2     |         4         |      2     | iv + ciphertext + mac length |
            ///
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \param[out] ciphertext Where to write encrypted ciphertext.
            /// \return Number of bytes written to ciphertext.
            std::size_t Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext);
            /// \beief
            /// Encrypt and mac plaintext. This function is a wrapper which allocates a buffer
            /// and calls Encrypt above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \return An encrypted and mac'ed buffer.
            util::Buffer Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0);

            /// \brief
            /// Encrypt, mac, and enlengthen plaintext. It writes the following structure in to ciphertext:
            ///
            /// |--- FrameHeader ---|---------- \see{CiphertextHeader} ----------|--------- ciphertext ---------|
            /// +-------------------+-----------+-------------------+------------+------+---------------+-------+
            /// | ciphertext length | iv length | ciphertext length | mac length |  iv  |  ciphertext   |  mac  |
            /// +-------------------+-----------+-------------------+------------+------+---------------+-------+
            /// |         4         |     2     |         4         |      2     | iv + ciphertext + mac length |
            ///
            /// NOTE: FrameHeader::ciphertext length refers to everything that follows (\see{CiphertextHeader} + ciphertext).
            ///
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \param[out] ciphertext Where to write encrypted ciphertext.
            /// \return Number of bytes written to ciphertext.
            std::size_t EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext);
            /// \brief
            /// Encrypt, mac and enlengthen plaintext. Similar to Encrypt above but allocates a
            /// buffer large enough to hold a util::ui32 containing the ciphertext length and
            /// calls EncryptAndEnlengthen above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \return An encrypted, mac'ed and framed buffer.
            util::Buffer EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength);

            /// \brief
            /// Encrypt, mac, and frame plaintext. It writes the following structure in to ciphertext:
            ///
            /// |----- \see{FrameHeader} ----|---------- \see{CiphertextHeader} ----------|--------- ciphertext ---------|
            /// +--------+-------------------+-----------+-------------------+------------+------+---------------+-------+
            /// | key id | ciphertext length | iv length | ciphertext length | mac length |  iv  |  ciphertext   |  mac  |
            /// +--------+-------------------+-----------+-------------------+------------+------+---------------+-------+
            /// |   32   |         4         |     2     |         4         |      2     | iv + ciphertext + mac length |
            ///
            /// NOTE: FrameHeader::ciphertext length refers to everything that follows (\see{CiphertextHeader} + ciphertext).
            ///
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \param[out] ciphertext Where to write encrypted ciphertext.
            /// \return Number of bytes written to ciphertext.
            std::size_t EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext);
            /// \brief
            /// Encrypt, mac and frame plaintext. Similar to Encrypt above but allocates a
            /// buffer large enough to hold a \see{FrameHeader} containing the key id and
            /// ciphertext length and calls EncryptAndFrame above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Plaintext length.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \return An encrypted, mac'ed and framed buffer.
            util::Buffer EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0);

            /// \brief
            /// Verify the ciphertext MAC and, if matches, decrypt it.
            /// \param[in] ciphertext \see{CiphertextHeader}, IV, ciphertext and MAC
            /// returned by the first Encrypt above.
            /// \param[in] ciphertextLength Length of ciphertext.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \param[out] plaintext Where to write the decrypted plain text.
            /// \return Number of bytes written to plaintext.
            std::size_t Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *plaintext);
            /// \brief
            /// Verify the ciphertext MAC and, if matches, decrypt it.
            /// \param[in] ciphertext \see{CiphertextHeader}, IV, ciphertext and MAC
            /// returned the first of Encrypt above.
            /// \param[in] ciphertextLength Length of ciphertext.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            /// \param[in] secure true == return util::SecureBuffer.
            /// \param[in] endianness Resulting plaintext buffer endianness.
            /// \return Plaintext.
            util::Buffer Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0,
                bool secure = false,
                util::Endianness endianness = util::NetworkEndian);

            /// \brief
            /// Cipher is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Cipher)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Cipher_h)
