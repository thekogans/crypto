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

#if !defined (__thekogans_crypto_RSA_h)
#define __thekogans_crypto_RSA_h

#include <cstddef>
#include <string>
#include <openssl/rsa.h>
#include "thekogans/util/ByteSwap.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct RSA RSA.h thekogans/crypto/RSA.h
        ///
        /// \brief
        /// Use RSA to generate private/public key pairs that can be used for
        /// key exchange (\see{RSAKeyExchange}) and sign/verify (\see{Authenticator})
        /// operations. RSA is also used to perform asymmetric encryption/decryption.

        struct _LIB_THEKOGANS_CRYPTO_DECL RSA {
            /// \brief
            /// Create an RSA key.
            /// \param[in] keyLength The length of the key (in bits).
            /// \param[in] publicExponent RSA key public exponent.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new RSA key.
            static AsymmetricKey::Ptr CreateKey (
                std::size_t keyLength,
                BIGNUMPtr publicExponent = BIGNUMFromui32 (65537),
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the max plaintextLength that can be passed to EncryptBuffer below.
            /// \param[in] keyLength Length of key (in bits).
            /// \param[in] paddin OpenSSL RSA padding type.
            /// \return Max plaintextLength that can be passed to EncryptBuffer below.
            static std::size_t GetMaxPlaintextLength (
                std::size_t keyLength,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING);

            /// \brief
            /// Use the public key to encrypt the plaintext. This is the workhorse
            /// RSA encryption method used by all others below.
            /// NOTE: Asymmetric encryption is very slow and should not be used
            /// for bulk encryption duties (See \see{Cipher} for that). You should
            /// only use it to encrypt message digests (See \see{MessageDigest}) or
            /// \see{SymmetricKey} during key exchange.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \param[out] ciphertext Where to write the ciphertext.
            /// \return Number of bytes written to ciphertext.
            /// VERY IMPORTANT: plaintextLength must be <= keyLength / 8 - padding length.
            /// Ex: For a 1024 bit key, using RSA_PKCS1_OAEP_PADDING, plaintextLength <=
            /// 1024 / 8 – 42 = 128 – 42 = 86.
            static std::size_t Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext);
            /// \brief
            /// Allocate a buffer large enough and call Encrypt above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \return Encrypted plaintext.
            static util::Buffer Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING);

            /// \brief
            /// Similar to Encrypt above but appends the length of the generated ciphertext.
            /// \see{SymmetricKey} during key exchange.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \param[out] ciphertext Where to write the ciphertext.
            /// \return Number of bytes written to ciphertext.
            static std::size_t EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext);
            /// \brief
            /// Allocate a buffer large enough and call EncryptAndEnlengthen above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \return Encrypted plaintext.
            static util::Buffer EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING);

            /// \brief
            /// Similar to Encrypt above but appends a \see{FrameHeader} to the generated ciphertext.
            /// \see{SymmetricKey} during key exchange.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \param[out] ciphertext Where to write the ciphertext.
            /// \return Number of bytes written to ciphertext.
            static std::size_t EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext);
            /// \brief
            /// Allocate a buffer large enough and call EncryptAndFrame above.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \return Encrypted plaintext.
            static util::Buffer EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING);

            /// \brief
            /// Use the private key to decrypt the ciphertext.
            /// \param[in] ciphertext Ciphertext to decrypt.
            /// \param[in] ciphertextLength Length of ciphertext.
            /// \param[in] privateKey Private key used for decryption.
            /// \param[in] padding RSA padding type.
            /// \param[out] plaintext Where to write decrypted plaintext.
            /// \return Number of bytes written to plaintext.
            static std::size_t Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding,
                util::ui8 *plaintext);
            /// \brief
            /// Use the private key to decrypt the ciphertext.
            /// \param[in] ciphertext Ciphertext to decrypt.
            /// \param[in] ciphertextLength Length of ciphertext.
            /// \param[in] privateKey Private key used for decryption.
            /// \param[in] padding RSA padding type.
            /// \param[in] secure true == return util::SecureBuffer.
            /// \param[in] endianness Endianness type of the resulting plaintext.
            /// \return Decrypted ciphertext.
            static util::Buffer Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING,
                bool secure = false,
                util::Endianness endianness = util::NetworkEndian);
        };

        /// \brief
        /// Gets around the RSA::Encrypt plaintextLength limitation by creating
        /// a random \see{SymmetricKey}, using it to encrypt plaintext, and then
        /// using the given publicKey to encrypt the random key.
        /// NOTE: The minimum amount of data that the given publicKey will need
        /// to be able to encrypt is 18 bytes (util::UI8_SIZE + util::UI8_SIZE + 16).
        /// Since RSA_PKCS1_OAEP_PADDING padding needs 42 bytes, the smallest RSA
        /// key using it needs to be 512 bits. If you need to use smaller RSA keys,
        /// you will need to use different form of padding (RSA_PKCS1_PADDING).
        /// \param[in] plaintext Plaintext to encrypt.
        /// \param[in] plaintextLength Length of plaintext.
        /// \param[in] publicKey Public key used to encrypt the generated random
        /// \see{SymmetricKey} encryption.
        /// \param[in] padding RSA padding type.
        /// \param[out] ciphertext Where to write the encrypted plaintext.
        /// \return Number of bytes written to ciphertext.
        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
            RSAEncrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext);
        /// \brief
        /// Gets around the RSA::Encrypt plaintextLength limitation by creating
        /// a random \see{SymmetricKey}, using it to encrypt plaintext, and then
        /// using the given publicKey to encrypt the random key.
        /// NOTE: The minimum amount of data that the given publicKey will need
        /// to be able to encrypt is 18 bytes (util::UI8_SIZE + util::UI8_SIZE + 16).
        /// Since RSA_PKCS1_OAEP_PADDING padding needs 42 bytes, the smallest RSA
        /// key using it needs to be 512 bits. If you need to use smaller RSA keys,
        /// you will need to use different form of padding (RSA_PKCS1_PADDING).
        /// \param[in] plaintext Plaintext to encrypt.
        /// \param[in] plaintextLength Length of plaintext.
        /// \param[in] publicKey Public key used to encrypt the generated random
        /// \see{SymmetricKey} encryption.
        /// \param[in] padding RSA padding type.
        /// \return Encrypted plaintext.
        _LIB_THEKOGANS_CRYPTO_DECL util::Buffer _LIB_THEKOGANS_CRYPTO_API
            RSAEncrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING);

        /// \brief
        /// Decrypts the ciphertext produced by RSAEncrypt above.
        /// \param[in] ciphertext Ciphertext to decrypt.
        /// \param[in] ciphertextLength Length of ciphertext.
        /// \param[in] privateKey Private key used for decryption.
        /// \param[in] padding RSA padding type.
        /// \param[out] plaintext Where to write the decrypted ciphertext.
        /// \return Number of bytes written to plaintext.
        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
            RSADecrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding,
                util::ui8 *plaintext);
        /// \brief
        /// Decrypts the ciphertext produced by RSAEncrypt above.
        /// \param[in] ciphertext Ciphertext to decrypt.
        /// \param[in] ciphertextLength Length of ciphertext.
        /// \param[in] privateKey Private key used for decryption.
        /// \param[in] padding RSA padding type.
        /// \param[in] secure true == return util::SecureBuffer.
        /// \param[in] endianness Endianness type of the resulting plaintext.
        /// \return Decrypted ciphertext.
        _LIB_THEKOGANS_CRYPTO_DECL util::Buffer _LIB_THEKOGANS_CRYPTO_API
            RSADecrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING,
                bool secure = false,
                util::Endianness endianness = util::NetworkEndian);

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_RSA_h)
