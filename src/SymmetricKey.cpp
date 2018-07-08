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

#if defined (THEKOGANS_CRYPTO_TESTING)
    #include <sstream>
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include <algorithm>
#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    #include <argon2.h>
#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
#include <openssl/evp.h>
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/XMLUtils.h"
    #include "thekogans/util/StringUtils.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "fastpbkdf2.h"
#include "thekogans/crypto/MessageDigest.h"
#include "thekogans/crypto/Argon2Exception.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/SymmetricKey.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            SymmetricKey,
            1,
            THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)

    #if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
        SymmetricKey::Ptr SymmetricKey::FromArgon2 (
                argon2_context &context,
                std::size_t keyLength,
                argon2_ctx_fptr argon2_ctx,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (keyLength > 0 && argon2_ctx != 0) {
                uint8_t *out = context.out;
                uint32_t outlen = context.outlen;
                util::SecureVector<util::ui8> key (keyLength);
                context.out = key.data ();
                context.outlen = (uint32_t)key.size ();
                int errorCode = argon2_ctx (&context);
                context.out = out;
                context.outlen = outlen;
                if (errorCode == ARGON2_OK) {
                    return Ptr (new SymmetricKey (key.data (), key.size (), id, name, description));
                }
                else {
                    THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION (errorCode);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }
    #endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)

        SymmetricKey::Ptr SymmetricKey::FromPBKDF2 (
                const void *password,
                std::size_t passwordLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                PBKDF2_HMAC hash,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (password != 0 && passwordLength > 0 &&
                    keyLength > 0 && count > 0) {
                util::SecureVector<util::ui8> key (keyLength);
                switch (hash) {
                    case PBKDF2_HMAC_SHA1:
                        fastpbkdf2_hmac_sha1 (
                            (const uint8_t *)password,
                            (uint32_t)passwordLength,
                            (const uint8_t *)salt,
                            (uint32_t)saltLength,
                            (uint32_t)count,
                            key.data (),
                            (uint32_t)key.size ());
                        break;
                    case PBKDF2_HMAC_SHA256:
                        fastpbkdf2_hmac_sha256 (
                            (const uint8_t *)password,
                            (uint32_t)passwordLength,
                            (const uint8_t *)salt,
                            (uint32_t)saltLength,
                            (uint32_t)count,
                            key.data (),
                            (uint32_t)key.size ());
                        break;
                    case PBKDF2_HMAC_SHA512:
                        fastpbkdf2_hmac_sha512 (
                            (const uint8_t *)password,
                            (uint32_t)passwordLength,
                            (const uint8_t *)salt,
                            (uint32_t)saltLength,
                            (uint32_t)count,
                            key.data (),
                            (uint32_t)key.size ());
                        break;
                }
                return Ptr (new SymmetricKey (key.data (), key.size (), id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr SymmetricKey::FromOpenSSLPBKDF2 (
                const void *password,
                std::size_t passwordLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (password != 0 && passwordLength > 0 &&
                    keyLength > 0 && md != 0 && count > 0) {
                util::SecureVector<util::ui8> key (keyLength);
                if (PKCS5_PBKDF2_HMAC (
                        (const char *)password,
                        (int)passwordLength,
                        (const unsigned char *)salt,
                        (int)saltLength,
                        (int)count,
                        md,
                        (int)key.size (),
                        key.data ()) == 1) {
                    return Ptr (new SymmetricKey (key.data (), key.size (), id, name, description));
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr SymmetricKey::FromSecretAndSalt (
                const void *secret,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (secret != 0 && secretLength > 0 &&
                    keyLength > 0 && md != 0 && count > 0) {
                util::SecureVector<util::ui8> key (keyLength);
                keyLength = 0;
                util::SecureVector<util::ui8> buffer (EVP_MAX_MD_SIZE);
                std::size_t bufferLength = 0;
                MessageDigest messageDigest (md);
                while (keyLength < key.size ()) {
                    messageDigest.Init ();
                    if (bufferLength > 0) {
                        messageDigest.Update (buffer.data (), bufferLength);
                    }
                    messageDigest.Update (secret, secretLength);
                    if (salt != 0 && saltLength > 0) {
                        messageDigest.Update (salt, saltLength);
                    }
                    bufferLength = messageDigest.Final (buffer.data ());
                    for (util::ui32 i = 1; i < count; ++i) {
                        messageDigest.Init ();
                        messageDigest.Update (buffer.data (), bufferLength);
                        bufferLength = messageDigest.Final (buffer.data ());
                    }
                    std::size_t count = std::min (key.size () - keyLength, bufferLength);
                    memcpy (&key[keyLength], buffer.data (), count);
                    keyLength += count;
                }
                return Ptr (new SymmetricKey (key.data (), key.size (), id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr SymmetricKey::FromRandom (
                std::size_t randomLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (randomLength < MIN_RANDOM_LENGTH) {
                randomLength = MIN_RANDOM_LENGTH;
            }
            util::SecureVector<util::ui8> random (randomLength);
            if (util::GlobalRandomSource::Instance ().GetBytes (&random[0], randomLength) == randomLength) {
                return FromSecretAndSalt (
                    &random[0],
                    randomLength,
                    salt,
                    saltLength,
                    keyLength,
                    md,
                    count,
                    id,
                    name,
                    description);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to get %u random bytes for key.", randomLength);
            }
        }

        std::size_t SymmetricKey::Size () const {
            return
                Serializable::Size () +
                util::UI32_SIZE + key.GetDataAvailableForReading ();
        }

        void SymmetricKey::Read (
                const Header &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
            serializer >> key.writeOffset;
            serializer.Read (key.data, key.GetDataAvailableForReading ());
            memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
        }

        void SymmetricKey::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
            serializer << key.GetDataAvailableForReading ();
            serializer.Write (key.GetReadPtr (), key.GetDataAvailableForReading ());
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        std::string SymmetricKey::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_TYPE, Type ()));
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                util::HexEncodeBuffer (key.GetReadPtr (), key.GetDataAvailableForReading ()) << std::endl <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
