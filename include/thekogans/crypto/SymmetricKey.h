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

#if !defined (__thekogans_crypto_SymmetricKey_h)
#define __thekogans_crypto_SymmetricKey_h

#include <cstddef>
#include <string>
#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    #include <argon2.h>
#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/FixedBuffer.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct SymmetricKey SymmetricKey.h thekogans/crypto/SymmetricKey.h
        ///
        /// \brief
        /// SymmetricKey is used by \see{Cipher} for bulk encryption.

        struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey : public Serializable {
            /// \brief
            /// SymmetricKey is a \see{Serializable}
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (SymmetricKey)

        private:
            /// \brief
            /// Symmetric key.
            util::FixedBuffer<EVP_MAX_KEY_LENGTH> key;

        public:
            /// \brief
            /// ctor.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \param[in] begin Option start of key.
            /// \param[in] end Option end of key.
            SymmetricKey (
                    const void *buffer = 0,
                    std::size_t length = 0,
                    const ID &id = ID (),
                    const std::string &name = std::string (),
                    const std::string &description = std::string ()) :
                    Serializable (id, name, description),
                    // FixedBuffer will throw if length > EVP_MAX_KEY_LENGTH.
                    key (util::HostEndian, (const util::ui8 *)buffer, length) {
                memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
            }
            ~SymmetricKey () {
                memset (key.data, 0, EVP_MAX_KEY_LENGTH);
            }

            /// \brief
            /// Return the key length (in bytes).
            /// \return Key length (in bytes).
            inline std::size_t GetKeyLength () const {
                return key.GetDataAvailableForReading ();
            }

        #if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
            /// \brief
            /// Convenient typedef int (*) (argon2_context *context).
            typedef int (*argon2_ctx_fptr) (argon2_context *context);

            /// \brief
            /// Use Argon2 password-hashing function to derive a key.
            /// \param[in] context An initialized Argon2 context.
            /// NOTE: context.out and context.outlen should be initialized
            /// to 0 as this method will set them internally before calling
            /// argon2_ctx.
            /// NOTE: Not only is salt NOT optional, but it must be at least
            /// 8 bytes long.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] argon2_ctx Argon2 function to use for key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromArgon2 (
                argon2_context &context,
                std::size_t keyLength = GetCipherKeyLength (),
                argon2_ctx_fptr argon2_ctx = argon2id_ctx,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
        #endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)

            /// \brief
            /// Generate a key using PBKDF1.
            /// WARNING: As per spec, PBKDF1 does not do key stretching. Keep
            /// that in mind when choosing an md for a particular keyLength.
            /// \param[in] password Password from which to derive the key.
            /// \param[in] passwordLength Password length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// WARNING: PBKDF1 salt is limited to 8 bytes.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] timeInSeconds A security measure. Provide a value > 0 to
            /// slow down key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromPBKDF1 (
                const void *password,
                std::size_t passwordLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                util::f64 timeInSeconds = 0.0,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// FromPBKDF2 hmac types.
            enum PBKDF2_HMAC {
                /// \brief
                /// SHA1
                PBKDF2_HMAC_SHA1,
                /// \brief
                /// SHA256
                PBKDF2_HMAC_SHA256,
                /// \brief
                /// SHA512
                PBKDF2_HMAC_SHA512
            };

            /// \brief
            /// Generate a key using PBKDF2.
            /// \param[in] password Password from which to derive the key.
            /// \param[in] passwordLength Password length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] hash Hash function.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromPBKDF2 (
                const void *password,
                std::size_t passwordLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                PBKDF2_HMAC hash = PBKDF2_HMAC_SHA256,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Generate a key using OpeSSL's implementation of PBKDF2.
            /// \param[in] password Password from which to derive the key.
            /// \param[in] passwordLength Password length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromOpenSSLPBKDF2 (
                const void *password,
                std::size_t passwordLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// FromHKDF mode types.
            enum HKDF_MODE {
                /// \brief
                /// Both salt and info are provided.
                HKDF_MODE_EXTRACT_AND_EXPAND,
                /// \brief
                /// Only salt is provided.
                HKDF_MODE_EXTRACT_ONLY,
                /// \brief
                /// Only info is provided.
                HKDF_MODE_EXPAND_ONLY
            };

            /// \brief
            /// Generate a key using HKDF (RFC 5869).
            /// \param[in] hmacKey HMAC key.
            /// \param[in] hmacKeyLength HMAC key length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] info An optional buffer containing info.
            /// \param[in] infoLength Info length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] mode One of HKDF_MODE_EXTRACT_AND_EXPAND,
            /// HKDF_MODE_EXTRACT_ONLY or HKDF_MODE_EXPAND_ONLY.
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromHKDF (
                const void *hmacKey,
                std::size_t hmacKeyLength,
                const void *salt,
                std::size_t saltLength,
                const void *info,
                std::size_t infoLength,
                std::size_t keyLength = GetCipherKeyLength (),
                HKDF_MODE mode = HKDF_MODE_EXTRACT_AND_EXPAND,
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Generate a key given secret (password) and length.
            /// \param[in] secret Shared secret from which to derive the key.
            /// \param[in] secretLength Shared secret length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromSecretAndSalt (
                const void *secret,
                std::size_t secretLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            enum {
                /// \brief
                /// Minimum length of random buffer to use in FromRandom.
                MIN_RANDOM_LENGTH = 256
            };

            /// \brief
            /// Generate a random key.
            /// \param[in] randomLength Length of random buffer from which
            /// keying material is derived.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromRandom (
                std::size_t randomLength = MIN_RANDOM_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the key buffer.
            /// \return Key buffer.
            inline const util::FixedBuffer<EVP_MAX_KEY_LENGTH> &Get () const {
                return key;
            }

        protected:
            // Serializable
            /// \brief
            /// Return the serialized key size.
            /// \return Serialized key size.
            virtual std::size_t Size () const;

            /// \brief
            /// Read the key from the given serializer.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the key from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer);
            /// \brief
            /// Write the key to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the key to.
            virtual void Write (util::Serializer &serializer) const;

        public:
            /// \brief
            /// "KeyLength"
            static const char * const ATTR_KEY_LENGTH;

            /// \brief
            /// Return the XML representation of a key.
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of a key.
            virtual std::string ToString (
                std::size_t indentationLevel = 0,
                const char *tagName = TAG_SERIALIZABLE) const;

            /// \brief
            /// SymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (SymmetricKey)
        };

        /// \brief
        /// Implement SymmetricKey extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (SymmetricKey)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_SymmetricKey_h)
