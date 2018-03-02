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
        /// key exchange (\see{KeyExchange}) and sign/verify (\see{Authenticator})
        /// operations. RSA is also used to perform asymmetric encryption/decryption.

        struct _LIB_THEKOGANS_CRYPTO_DECL RSA {
            /// \brief
            /// Create an RSA key.
            /// \param[in] keyLength The length of the key.
            /// \param[in] publicExponent RSA key public exponent.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new RSA key.
            static AsymmetricKey::Ptr CreateKey (
                std::size_t keyLength,
                BIGNUMPtr publicExponent = BIGNUMFromui32 (65537),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Use the public key to encrypt the plaintext.
            /// NOTE: Asymmetric encryption is very slow and should not be used
            /// for bulk encryption duties (See \see{Cipher} for that). You should
            /// only use it to encrypt message digests (See \see{MessageDigest}) or
            /// \see{SymmetricKey} during key exchange.
            /// \param[in] plaintext Plaintext to encrypt.
            /// \param[in] plaintextLength Length of plaintext.
            /// \param[in] publicKey Public key used for encryption.
            /// \param[in] padding RSA padding type.
            /// \return Encrypted plaintext.
            static util::Buffer::UniquePtr EncryptBuffer (
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
            /// \param[in] endianness Endianness type of the resulting plaintext.
            /// \return Decrypted ciphertext.
            static util::Buffer::UniquePtr DecryptBuffer (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding = RSA_PKCS1_OAEP_PADDING,
                util::Endianness endianness = util::NetworkEndian);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_RSA_h)
