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
#include <openssl/evp.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
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

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPrivateKeyFromBuffer (
                const std::string encoding,
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (buffer != 0 && length > 0) {
                BIOPtr bio (BIO_new_mem_buf (buffer, (int)length));
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPrivateKeyFromFile (
                const std::string encoding,
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

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPublicKeyFromBuffer (
                const std::string encoding,
                const void *buffer,
                std::size_t length,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (buffer != 0 && length > 0) {
                BIOPtr bio (BIO_new_mem_buf (buffer, (int)length));
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        AsymmetricKey::Ptr OpenSSLAsymmetricKey::LoadPublicKeyFromFile (
                const std::string encoding,
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
                const std::string encoding,
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
                const std::string encoding,
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
                EVP_PKEYPtr publicKey (PEM_read_bio_PUBKEY (bio.get (), 0, 0, 0));
                if (publicKey.get () != 0) {
                    return AsymmetricKey::Ptr (
                        new OpenSSLAsymmetricKey (
                            std::move (publicKey),
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

        namespace {
            util::SecureString WriteKey (
                    bool isPrivate,
                    EVP_PKEY &key) {
                BIOPtr bio (BIO_new (BIO_s_mem ()));
                if (bio.get () != 0 && (isPrivate ?
                        PEM_write_bio_PrivateKey (bio.get (), &key, 0, 0, 0, 0, 0) :
                        PEM_write_bio_PUBKEY (bio.get (), &key)) == 1) {
                    char *buffer = 0;
                    long length = BIO_get_mem_data (bio.get (), &buffer);
                    if (buffer != 0 && length > 0) {
                        return util::SecureString (buffer, buffer + length);
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
        }

        std::size_t OpenSSLAsymmetricKey::Size () const {
            return
                AsymmetricKey::Size () +
                util::Serializer::Size (WriteKey (IsPrivate (), *key)); // key
        }

        namespace {
            EVP_PKEYPtr ReadKey (
                    bool isPrivate,
                    const util::SecureString &keyBuffer) {
                BIOPtr bio (BIO_new (BIO_s_mem ()));
                if (bio.get () != 0) {
                    if (BIO_write (bio.get (), keyBuffer.data (), (int)keyBuffer.size ()) == (int)keyBuffer.size ()) {
                        return EVP_PKEYPtr (isPrivate ?
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
        }

        void OpenSSLAsymmetricKey::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            AsymmetricKey::Read (header, serializer);
            util::SecureString keyBuffer;
            serializer >> keyBuffer;
            key = ReadKey (IsPrivate (), keyBuffer);
        }

        void OpenSSLAsymmetricKey::Write (util::Serializer &serializer) const {
            AsymmetricKey::Write (serializer);
            serializer << WriteKey (IsPrivate (), *key);
        }

        void OpenSSLAsymmetricKey::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            AsymmetricKey::Read (header, node);
            key = ReadKey (IsPrivate (), util::SecureString (node.text ().get ()));
        }

        void OpenSSLAsymmetricKey::Write (pugi::xml_node &node) const {
            AsymmetricKey::Write (node);
            node.append_child (pugi::node_pcdata).set_value (WriteKey (IsPrivate (), *key).c_str ());
        }

        void OpenSSLAsymmetricKey::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            AsymmetricKey::Read (header, object);
            // FIXME: implement
            assert (0);
        }

        void OpenSSLAsymmetricKey::Write (util::JSON::Object &object) const {
            AsymmetricKey::Write (object);
            // FIXME: implement
            assert (0);
        }

    } // namespace crypto
} // namespace thekogans
