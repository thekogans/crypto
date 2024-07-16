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

#include <sstream>
#include <algorithm>
#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
    #include <argon2.h>
#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "thekogans/util/SizeT.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/HRTimer.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/crypto/MessageDigest.h"
#include "thekogans/crypto/Argon2Exception.h"
#include "thekogans/crypto/fastpbkdf2.h"
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
        SymmetricKey::SharedPtr SymmetricKey::FromArgon2 (
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
                    return SharedPtr (new SymmetricKey (key.data (), key.size (), id, name, description));
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

        SymmetricKey::SharedPtr SymmetricKey::FromPBKDF1 (
                const void *password,
                std::size_t passwordLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                util::f64 timeInSeconds,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (password != 0 && passwordLength > 0 &&
                    (salt == 0 || saltLength == 8) &&
                    keyLength > 0 && keyLength <= GetMDLength (md) &&
                    md != 0 && count > 0) {
                MessageDigest messageDigest (md);
                messageDigest.Update (password, passwordLength);
                if (salt != 0 && saltLength > 0) {
                    messageDigest.Update (salt, saltLength);
                }
                util::SecureVector<util::ui8> buffer (EVP_MAX_MD_SIZE);
                std::size_t bufferLength = messageDigest.Final (buffer.data ());
                util::ui64 start = util::HRTimer::Click ();
                util::f64 elapsedSeconds = 0.0;
                for (std::size_t i = 1;
                        i < count || (timeInSeconds != 0.0 && (i % 128 != 0 || elapsedSeconds < timeInSeconds));
                        ++i) {
                    messageDigest.Init ();
                    messageDigest.Update (buffer.data (), bufferLength);
                    bufferLength = messageDigest.Final (buffer.data ());
                    elapsedSeconds = util::HRTimer::ToSeconds (
                        util::HRTimer::ComputeElapsedTime (start, util::HRTimer::Click ()));
                }
                return SharedPtr (new SymmetricKey (buffer.data (), keyLength, id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::SharedPtr SymmetricKey::FromPBKDF2 (
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
                return SharedPtr (new SymmetricKey (key.data (), key.size (), id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::SharedPtr SymmetricKey::FromOpenSSLPBKDF2 (
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
                    return SharedPtr (new SymmetricKey (key.data (), key.size (), id, name, description));
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

        namespace {
            void HKDF_Extract (
                    const void *hmacKey,
                    std::size_t hmacKeyLength,
                    const void *salt,
                    std::size_t saltLength,
                    const EVP_MD *md,
                    util::SecureVector<util::ui8> &prk) {
                util::ui32 length;
                if (HMAC (md,
                            salt,
                            (int)saltLength,
                            (const util::ui8 *)hmacKey,
                            (int)hmacKeyLength,
                            prk.data (),
                            &length) != 0) {
                    prk.resize (length);
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }

            void HKDF_Expand (
                    const void *prk,
                    std::size_t prkLength,
                    const void *info,
                    std::size_t infoLength,
                    const EVP_MD *md,
                    util::SecureVector<util::ui8> &key) {
                HMACContext ctx;
                if (HMAC_Init_ex (
                            &ctx,
                            (const util::ui8 *)prk,
                            (int)prkLength,
                            md,
                            OpenSSLInit::engine) == 1) {
                    std::vector<util::ui8> digest (GetMDLength (md));
                    std::size_t count = key.size () / digest.size ();
                    if ((key.size () % digest.size ()) != 0) {
                        ++count;
                    }
                    for (std::size_t i = 1, offset = 0; i <= count; ++i) {
                        if (i > 1) {
                            if (HMAC_Init_ex (&ctx, 0, 0, 0, 0) != 1 ||
                                    HMAC_Update (&ctx, digest.data (), digest.size ()) != 1) {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        const util::ui8 counter = (util::ui8)i;
                        if (HMAC_Update (&ctx, (const util::ui8 *)info, infoLength) == 1 &&
                                HMAC_Update (&ctx, &counter, 1) == 1 &&
                                HMAC_Final (&ctx, digest.data (), 0) == 1) {
                            std::size_t length = offset + digest.size () > key.size () ?
                                key.size () - offset :
                                offset;
                            memcpy (&key[offset], digest.data (), length);
                            offset += length;
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                }
            }

            void HKDF (
                    const void *hmacKey,
                    std::size_t hmacKeyLength,
                    const void *salt,
                    std::size_t saltLength,
                    const void *info,
                    std::size_t infoLength,
                    const EVP_MD *md,
                    util::SecureVector<util::ui8> &key) {
                util::SecureVector<util::ui8> prk (EVP_MAX_MD_SIZE);
                HKDF_Extract (hmacKey, hmacKeyLength, salt, saltLength, md, prk);
                HKDF_Expand (prk.data (), prk.size (), info, infoLength, md, key);
            }
        }

        SymmetricKey::SharedPtr SymmetricKey::FromHKDF (
                const void *hmacKey,
                std::size_t hmacKeyLength,
                const void *salt,
                std::size_t saltLength,
                const void *info,
                std::size_t infoLength,
                std::size_t keyLength,
                HKDF_MODE mode,
                const EVP_MD *md,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (hmacKey != 0 && hmacKeyLength > 0 && keyLength > 0 && md != 0) {
                util::SecureVector<util::ui8> key (keyLength);
                switch (mode) {
                    case HKDF_MODE_EXTRACT_AND_EXPAND:
                        if (salt != 0 && saltLength > 0 && info != 0 && infoLength > 0) {
                            HKDF (
                                hmacKey,
                                hmacKeyLength,
                                salt,
                                saltLength,
                                info,
                                infoLength,
                                md,
                                key);
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                        }
                        break;
                    case HKDF_MODE_EXTRACT_ONLY:
                        if (salt != 0 && saltLength > 0) {
                            HKDF_Extract (
                                hmacKey,
                                hmacKeyLength,
                                salt,
                                saltLength,
                                md,
                                key);
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                        }
                        break;
                    case HKDF_MODE_EXPAND_ONLY:
                        if (info != 0 && infoLength > 0) {
                            HKDF_Expand (
                                hmacKey,
                                hmacKeyLength,
                                info,
                                infoLength,
                                md,
                                key);
                        }
                        else {
                            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                        }
                        break;
                }
                return SharedPtr (new SymmetricKey (key.data (), key.size (), id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::SharedPtr SymmetricKey::FromSecretAndSalt (
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
                    for (std::size_t i = 1; i < count; ++i) {
                        messageDigest.Init ();
                        messageDigest.Update (buffer.data (), bufferLength);
                        bufferLength = messageDigest.Final (buffer.data ());
                    }
                    std::size_t count = std::min (key.size () - keyLength, bufferLength);
                    memcpy (&key[keyLength], buffer.data (), count);
                    keyLength += count;
                }
                return SharedPtr (new SymmetricKey (key.data (), key.size (), id, name, description));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::SharedPtr SymmetricKey::FromRandom (
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
            if (util::GlobalRandomSource::Instance ()->GetSeedOrBytes (
                    random.data (), randomLength) == randomLength) {
                return FromSecretAndSalt (
                    random.data (),
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
                    "Unable to get " THEKOGANS_UTIL_SIZE_T_FORMAT " random bytes for key.",
                    randomLength);
            }
        }

        void SymmetricKey::Set (
                const void *buffer,
                std::size_t length) {
            if (buffer != 0 && length <= key.GetLength ()) {
                key.Rewind ();
                if (key.Write (buffer, length) == length) {
                    if (length < key.GetLength ()) {
                        memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to write " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes.", length);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t SymmetricKey::Size () const {
            return
                Serializable::Size () +
                util::SizeT (key.GetDataAvailableForReading ()).Size () +
                key.GetDataAvailableForReading ();
        }

        void SymmetricKey::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
            util::SizeT length;
            serializer >> length;
            if (length > 0 && length <= key.GetLength ()) {
                key.Rewind ();
                if (key.AdvanceWriteOffset (
                        serializer.Read (key.GetWritePtr (), length)) == length) {
                    memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to read " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes for key.", length);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid key size " THEKOGANS_UTIL_SIZE_T_FORMAT ".", length);
            }
        }

        void SymmetricKey::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
            serializer << util::SizeT (key.GetDataAvailableForReading ());
            if (serializer.Write (
                    key.GetReadPtr (),
                    key.GetDataAvailableForReading ()) != key.GetDataAvailableForReading ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to write " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes for key.",
                    key.GetDataAvailableForReading ());
            }
        }

        const char * const SymmetricKey::ATTR_KEY = "Key";

        void SymmetricKey::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            Serializable::Read (header, node);
            util::SecureString hexKey = node.attribute (ATTR_KEY).value ();
            std::size_t length = hexKey.size () / 2;
            if (length > 0 && length <= key.GetLength ()) {
                key.Rewind ();
                if (key.AdvanceWriteOffset (
                        util::HexDecodeBuffer (hexKey.data (), hexKey.size (), key.GetWritePtr ())) == length) {
                    memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to decode " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes for key.", length);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid key size " THEKOGANS_UTIL_SIZE_T_FORMAT ".", length);
            }
        }

        void SymmetricKey::Write (pugi::xml_node &node) const {
            Serializable::Write (node);
            node.append_attribute (ATTR_KEY).set_value (
                util::HexEncodeBuffer (
                    key.GetReadPtr (),
                    key.GetDataAvailableForReading ()).c_str ());
        }

        void SymmetricKey::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            Serializable::Read (header, object);
            util::SecureString hexKey = object.Get<util::JSON::String> (ATTR_KEY)->value.c_str ();
            std::size_t length = hexKey.size () / 2;
            if (length > 0 && length <= key.GetLength ()) {
                key.Rewind ();
                if (key.AdvanceWriteOffset (
                        util::HexDecodeBuffer (
                            hexKey.data (),
                            hexKey.size (),
                            key.GetWritePtr ())) == length) {
                    memset (key.GetWritePtr (), 0, key.GetDataAvailableForWriting ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to decode " THEKOGANS_UTIL_SIZE_T_FORMAT " bytes for key.", length);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid key size " THEKOGANS_UTIL_SIZE_T_FORMAT ".", length);
            }
        }

        void SymmetricKey::Write (util::JSON::Object &object) const {
            Serializable::Write (object);
            object.Add<const std::string &> (
                ATTR_KEY,
                util::HexEncodeBuffer (
                    key.GetReadPtr (),
                    key.GetDataAvailableForReading ()));
        }

    } // namespace crypto
} // namespace thekogans
