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
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/Exception.h"
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/StringUtils.h"
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_ASYMMETRIC_KEYS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_ASYMMETRIC_KEYS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_ASYMMETRIC_KEYS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            AsymmetricKey,
            THEKOGANS_CRYPTO_MIN_ASYMMETRIC_KEYS_IN_PAGE)

        AsymmetricKey::AsymmetricKey (util::Serializer &serializer) :
                Serializable (serializer) {
            util::i32 type;
            util::i32 keyLength;
            serializer >> isPrivate >> type >> keyLength;
            util::SecureVector<util::ui8> keyBuffer (keyLength);
            serializer.Read (&keyBuffer[0], keyLength);
            const util::ui8 *keyData = &keyBuffer[0];
            key.reset (isPrivate ?
                d2i_PrivateKey (type, 0, &keyData, keyLength) :
                d2i_PublicKey (type, 0, &keyData, keyLength));
        }

        AsymmetricKey::Ptr AsymmetricKey::LoadPrivateKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                return Ptr (
                    new AsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PrivateKey (bio.get (), 0, passwordCallback, userData)),
                        true,
                        name,
                        description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr AsymmetricKey::LoadPublicKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                return Ptr (
                    new AsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PUBKEY (bio.get (), 0, passwordCallback, userData)),
                        false,
                        name,
                        description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr AsymmetricKey::LoadPublicKeyFromCertificate (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                X509Ptr certificate (PEM_read_bio_X509 (bio.get (), 0, passwordCallback, userData));
                if (certificate.get () != 0) {
                    return Ptr (
                        new AsymmetricKey (
                            EVP_PKEYPtr (X509_get_pubkey (certificate.get ())),
                            false,
                            name,
                            description));
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr AsymmetricKey::GetPublicKey (
                const std::string &name,
                const std::string &description) const {
            BIOPtr bio (BIO_new (BIO_s_mem ()));
            if (PEM_write_bio_PUBKEY (bio.get (), key.get ()) == 1) {
                AsymmetricKey::Ptr publicKey (
                    new AsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PUBKEY (bio.get (), 0, 0, 0)),
                        false,
                        name,
                        description));
                if (publicKey->Get () != 0) {
                    return publicKey;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        std::size_t AsymmetricKey::Size (bool includeType) const {
            util::i32 keyLength = isPrivate ?
                i2d_PrivateKey (key.get (), 0) :
                i2d_PublicKey (key.get (), 0);
            if (keyLength <= 0) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
            return
                Serializable::Size (includeType) +
                util::BOOL_SIZE + // isPrivate
                util::I32_SIZE + // type
                util::I32_SIZE + // keyLength
                keyLength;
        }

        namespace {
            void SerializeKey (
                    bool isPrivate,
                    EVP_PKEY &key,
                    util::SecureVector<util::ui8> &keyBuffer) {
                if (isPrivate) {
                    util::i32 keyLength = i2d_PrivateKey (&key, 0);
                    if (keyLength > 0) {
                        keyBuffer.resize (keyLength);
                        util::ui8 *keyData = &keyBuffer[0];
                        i2d_PrivateKey (&key, &keyData);
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    util::i32 keyLength = i2d_PublicKey (&key, 0);
                    if (keyLength > 0) {
                        keyBuffer.resize (keyLength);
                        util::ui8 *keyData = &keyBuffer[0];
                        i2d_PublicKey (&key, &keyData);
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
        }

        void AsymmetricKey::Serialize (
                util::Serializer &serializer,
                bool includeType) const {
            Serializable::Serialize (serializer, includeType);
            util::SecureVector<util::ui8> keyBuffer;
            SerializeKey (isPrivate, *key, keyBuffer);
            serializer <<
                isPrivate <<
                (util::i32)EVP_PKEY_base_id (key.get ()) <<
                (util::i32)keyBuffer.size ();
            serializer.Write (&keyBuffer[0], (util::ui32)keyBuffer.size ());
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const AsymmetricKey::ATTR_PRIVATE = "Private";
        const char * const AsymmetricKey::ATTR_KEY_TYPE = "KeyType";

        namespace {
            std::string typeTostring (util::i32 type) {
                switch (type) {
                    case EVP_PKEY_RSA:
                        return "RSA";
                    case EVP_PKEY_RSA2:
                        return "RSA2";
                    case EVP_PKEY_DSA:
                        return "DSA";
                    case EVP_PKEY_DSA1:
                        return "DSA1";
                    case EVP_PKEY_DSA2:
                        return "DSA2";
                    case EVP_PKEY_DSA3:
                        return "DSA3";
                    case EVP_PKEY_DSA4:
                        return "DSA4";
                    case EVP_PKEY_DH:
                        return "DH";
                    case EVP_PKEY_DHX:
                        return "DHX";
                    case EVP_PKEY_EC:
                        return "EC";
                    case EVP_PKEY_HMAC:
                        return "HMAC";
                    case EVP_PKEY_CMAC:
                        return "CMAC";
                }
                return "unknown";
            }
        }

        std::string AsymmetricKey::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            util::SecureVector<util::ui8> keyBuffer;
            SerializeKey (isPrivate, *key, keyBuffer);
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_TYPE, Type ()));
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PRIVATE, util::boolTostring (isPrivate)));
            attributes.push_back (util::Attribute (ATTR_KEY_TYPE, typeTostring (EVP_PKEY_base_id (key.get ()))));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                std::string (keyBuffer.begin (), keyBuffer.end ()) << std::endl <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
