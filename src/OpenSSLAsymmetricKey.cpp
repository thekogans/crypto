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
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_OPENSSL_ASYMMETRIC_KEYS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_OPENSSL_ASYMMETRIC_KEYS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_OPENSSL_ASYMMETRIC_KEYS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            OpenSSLAsymmetricKey,
            1,
            THEKOGANS_CRYPTO_MIN_OPENSSL_ASYMMETRIC_KEYS_IN_PAGE)

        OpenSSLAsymmetricKey::OpenSSLAsymmetricKey (
                EVP_PKEYPtr key_,
                bool isPrivate,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                AsymmetricKey (isPrivate, id, name, description),
                key (std::move (key_)) {
            if (key.get () != 0) {
                const char *type = GetKeyType ();
                if (type != OPENSSL_PKEY_DH &&
                        type != OPENSSL_PKEY_DSA &&
                        type != OPENSSL_PKEY_EC &&
                        type != OPENSSL_PKEY_RSA &&
                        type != OPENSSL_PKEY_HMAC &&
                        type != OPENSSL_PKEY_CMAC) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid key type %d.", type);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPrivateKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                return AsymmetricKey::Ptr (
                    new OpenSSLAsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PrivateKey (bio.get (), 0, passwordCallback, userData)),
                        true,
                        id,
                        name,
                        description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPublicKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                return AsymmetricKey::Ptr (
                    new OpenSSLAsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PUBKEY (bio.get (), 0, passwordCallback, userData)),
                        false,
                        id,
                        name,
                        description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPublicKeyFromCertificate (
                const std::string &path,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            BIOPtr bio (BIO_new_file (path.c_str (), "r"));
            if (bio.get () != 0) {
                X509Ptr certificate (PEM_read_bio_X509 (bio.get (), 0, passwordCallback, userData));
                if (certificate.get () != 0) {
                    return AsymmetricKey::Ptr (
                        new OpenSSLAsymmetricKey (
                            EVP_PKEYPtr (X509_get_pubkey (certificate.get ())),
                            false,
                            id,
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

        void OpenSSLAsymmetricKey::Save (
                const std::string &path,
                const EVP_CIPHER *cipher,
                const void *symmetricKey,
                std::size_t symmetricKeyLength,
                pem_password_cb *passwordCallback,
                void *userData) {
            BIOPtr bio (BIO_new_file (path.c_str (), "w+"));
            if (bio.get () == 0 || (IsPrivate () ?
                    PEM_write_bio_PrivateKey (
                        bio.get (),
                        key.get (),
                        cipher,
                        (unsigned char *)symmetricKey,
                        (int)symmetricKeyLength,
                        passwordCallback,
                        userData) :
                    PEM_write_bio_PUBKEY (bio.get (), key.get ())) == 0) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::GetPublicKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            BIOPtr bio (BIO_new (BIO_s_mem ()));
            if (PEM_write_bio_PUBKEY (bio.get (), key.get ()) == 1) {
                OpenSSLAsymmetricKey *publicKeyPtr;
                AsymmetricKey::Ptr publicKey (
                    publicKeyPtr = new OpenSSLAsymmetricKey (
                        EVP_PKEYPtr (PEM_read_bio_PUBKEY (bio.get (), 0, 0, 0)),
                        false,
                        id,
                        name,
                        description));
                if (publicKeyPtr->GetKey () != 0) {
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

        std::size_t OpenSSLAsymmetricKey::Size () const {
            BIOPtr bio (BIO_new (BIO_s_mem ()));
            if (bio.get () != 0 && (IsPrivate () ?
                    PEM_write_bio_PrivateKey (bio.get (), key.get (), 0, 0, 0, 0, 0) :
                    PEM_write_bio_PUBKEY (bio.get (), key.get ())) == 1) {
                std::size_t keyLength = BIO_ctrl_pending (bio.get ());
                return
                    AsymmetricKey::Size () +
                    util::Serializer::Size (std::string (GetKeyType ())) + // type
                    util::SizeT (keyLength) + // keyLength
                    keyLength; // key
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        void OpenSSLAsymmetricKey::Read (
                const Header &header,
                util::Serializer &serializer) {
            AsymmetricKey::Read (header, serializer);
            std::string type;
            util::SizeT keyLength;
            serializer >> type >> keyLength;
            util::SecureVector<util::ui8> keyBuffer (keyLength);
            if (serializer.Read (&keyBuffer[0], keyLength) == keyLength) {
                BIOPtr bio (BIO_new (BIO_s_mem ()));
                if (bio.get () != 0) {
                    if (BIO_write (bio.get (), &keyBuffer[0], (int)keyLength) == keyLength) {
                        key.reset (IsPrivate () ?
                            PEM_read_bio_PrivateKey (bio.get (), 0, 0, 0) :
                            PEM_read_bio_PUBKEY (bio.get (), 0, 0, 0));
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Read (&keyBuffer[0], %u) != %u",
                    keyBuffer.size (),
                    keyBuffer.size ());
            }
        }

        namespace {
            void WriteKey (
                    bool isPrivate,
                    EVP_PKEY &key,
                    util::SecureVector<util::ui8> &keyBuffer) {
                BIOPtr bio (BIO_new (BIO_s_mem ()));
                if (bio.get () != 0 && (isPrivate ?
                        PEM_write_bio_PrivateKey (bio.get (), &key, 0, 0, 0, 0, 0) :
                        PEM_write_bio_PUBKEY (bio.get (), &key)) == 1) {
                    util::ui8 *ptr = 0;
                    keyBuffer.resize (BIO_get_mem_data (bio.get (), &ptr));
                    if (!keyBuffer.empty () && ptr != 0) {
                        memcpy (&keyBuffer[0], ptr, keyBuffer.size ());
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
        }

        void OpenSSLAsymmetricKey::Write (util::Serializer &serializer) const {
            AsymmetricKey::Write (serializer);
            util::SecureVector<util::ui8> keyBuffer;
            WriteKey (IsPrivate (), *key, keyBuffer);
            serializer << std::string (GetKeyType ()) << util::SizeT (keyBuffer.size ());
            if (serializer.Write (&keyBuffer[0], keyBuffer.size ()) !=
                    keyBuffer.size ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Write (&keyBuffer[0], %u) != %u",
                    keyBuffer.size (),
                    keyBuffer.size ());
            }
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        std::string OpenSSLAsymmetricKey::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            util::SecureVector<util::ui8> keyBuffer;
            WriteKey (IsPrivate (), *key, keyBuffer);
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_TYPE, Type ()));
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PRIVATE, util::boolTostring (IsPrivate ())));
            attributes.push_back (util::Attribute (ATTR_KEY_TYPE, GetKeyType ()));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                std::string (keyBuffer.begin (), keyBuffer.end ()) << std::endl <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
