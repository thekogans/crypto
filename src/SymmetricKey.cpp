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
#include <openssl/evp.h>
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/XMLUtils.h"
    #include "thekogans/util/StringUtils.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
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

        SymmetricKey::Ptr SymmetricKey::FromSecretAndSalt (
                std::size_t keyLength,
                const void *secret,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                const EVP_MD *md,
                std::size_t count,
                const std::string &name,
                const std::string &description) {
            if (keyLength > 0 &&
                    secret != 0 && secretLength > 0 &&
                    md != 0 && count > 0) {
                Ptr symmetricKey (new SymmetricKey (name, description));
                util::SecureVector<util::ui8> buffer (EVP_MAX_MD_SIZE);
                util::ui32 bufferLength = 0;
                MDContext context;
                while (keyLength > 0) {
                    if (EVP_DigestInit_ex (&context, md, OpenSSLInit::engine) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    if (bufferLength > 0) {
                        if (EVP_DigestUpdate (&context, &buffer[0], bufferLength) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    if (EVP_DigestUpdate (&context, secret, secretLength) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    if (salt != 0 && saltLength > 0) {
                        if (EVP_DigestUpdate (&context, salt, saltLength) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    if (EVP_DigestFinal_ex (&context, &buffer[0], &bufferLength) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    for (util::ui32 i = 1; i < count; ++i) {
                        if (EVP_DigestInit_ex (&context, 0, 0) != 1 ||
                                EVP_DigestUpdate (&context, &buffer[0], bufferLength) != 1 ||
                                EVP_DigestFinal_ex (&context, &buffer[0], &bufferLength) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    std::size_t count = std::min (keyLength, (std::size_t)bufferLength);
                    memcpy (symmetricKey->key.GetWritePtr (), &buffer[0], count);
                    symmetricKey->key.AdvanceWriteOffset ((util::ui32)count);
                    keyLength -= count;
                }
                memset (
                    symmetricKey->key.GetWritePtr (),
                    0,
                    symmetricKey->key.GetDataAvailableForWriting ());
                return symmetricKey;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr SymmetricKey::FromRandom (
                std::size_t keyLength,
                std::size_t randomLength,
                const void *salt,
                std::size_t saltLength,
                const EVP_MD *md,
                std::size_t count,
                const std::string &name,
                const std::string &description) {
            if (randomLength < MIN_RANDOM_LENGTH) {
                randomLength = MIN_RANDOM_LENGTH;
            }
            util::SecureVector<util::ui8> random (randomLength);
            if (util::GlobalRandomSource::Instance ().GetBytes (&random[0], randomLength) == randomLength) {
                return FromSecretAndSalt (
                    keyLength,
                    &random[0],
                    randomLength,
                    salt,
                    saltLength,
                    md,
                    count,
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
