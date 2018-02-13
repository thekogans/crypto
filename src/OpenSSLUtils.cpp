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

#include <algorithm>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        OpenSSLAllocator OpenSSLAllocator::Global;

        void *OpenSSLAllocator::Alloc (std::size_t size) {
            return size > 0 ? OPENSSL_malloc (size) : 0;
        }

        void OpenSSLAllocator::Free (
                void *ptr,
                std::size_t /*size*/) {
            if (ptr != 0) {
                OPENSSL_free (ptr);
            }
        }

        void BN_CTXDeleter::operator () (BN_CTX *ctx) {
            if (ctx != 0) {
                BN_CTX_free (ctx);
            }
        }

        void BIGNUMDeleter::operator () (BIGNUM *bn) {
            if (bn != 0) {
                BN_free (bn);
            }
        }

        void EVP_PKEY_CTXDeleter::operator () (EVP_PKEY_CTX *ctx) {
            if (ctx != 0) {
                EVP_PKEY_CTX_free (ctx);
            }
        }

        void EVP_PKEYDeleter::operator () (EVP_PKEY *key) {
            if (key != 0) {
                EVP_PKEY_free (key);
            }
        }

        void EC_GROUPDeleter::operator () (EC_GROUP *group) {
            if (group != 0) {
                EC_GROUP_free (group);
            }
        }

        void EC_POINTDeleter::operator () (EC_POINT *point) {
            if (point != 0) {
                EC_POINT_free (point);
            }
        }

        void EC_KEYDeleter::operator () (EC_KEY *key) {
            if (key != 0) {
                EC_KEY_free (key);
            }
        }

        void EVP_CIPHER_CTXDeleter::operator () (EVP_CIPHER_CTX *ctx) {
            if (ctx != 0) {
                EVP_CIPHER_CTX_free (ctx);
            }
        }

        void EVP_MD_CTXDeleter::operator () (EVP_MD_CTX *ctx) {
            if (ctx != 0) {
                EVP_MD_CTX_destroy (ctx);
            }
        }

        void BIODeleter::operator () (BIO *bio) {
            if (bio != 0) {
                BIO_free (bio);
            }
        }

        void X509_STOREDeleter::operator () (X509_STORE *store) {
            if (store != 0) {
                X509_STORE_free (store);
            }
        }

        void X509_CRLDeleter::operator () (X509_CRL *crl) {
            if (crl != 0) {
                X509_CRL_free (crl);
            }
        }

        void X509Deleter::operator () (X509 *x509) {
            if (x509 != 0) {
                X509_free (x509);
            }
        }

        void DHDeleter::operator () (DH *dh) {
            if (dh != 0) {
                DH_free (dh);
            }
        }

        void DSADeleter::operator () (DSA *dsa) {
            if (dsa != 0) {
                DSA_free (dsa);
            }
        }

        void RSADeleter::operator () (RSA *rsa) {
            if (rsa != 0) {
                RSA_free (rsa);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::string _LIB_THEKOGANS_CRYPTO_API
        EVP_PKEYtypeTostring (util::i32 type) {
            switch (type) {
                case EVP_PKEY_RSA:
                    return "RSA";
                case EVP_PKEY_DSA:
                    return "DSA";
                case EVP_PKEY_DH:
                    return "DH";
                case EVP_PKEY_EC:
                    return "EC";
                case EVP_PKEY_HMAC:
                    return "HMAC";
                case EVP_PKEY_CMAC:
                    return "CMAC";
            }
            return "unknown";
        }

        _LIB_THEKOGANS_CRYPTO_DECL BIGNUMPtr _LIB_THEKOGANS_CRYPTO_API
        BIGNUMFromui32 (util::ui32 value) {
            BIGNUMPtr bn (BN_new ());
            BN_set_word (bn.get (), value);
            return bn;
        }

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        namespace {
            inline const unsigned char *ASN1_STRING_get0_data (const ASN1_STRING *x) {
                return ASN1_STRING_data ((ASN1_STRING *)x);
            }
        }
    #endif // OPENSSL_VERSION_NUMBER < 0x10100000L

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        GetCRLDistributionPoints (
                X509 *cert,
                std::vector<std::string> &crlDistributionPoints) {
            if (cert != 0) {
                const STACK_OF (DIST_POINT) *distributionPoints =
                    (STACK_OF (DIST_POINT) *)X509_get_ext_d2i (cert, NID_crl_distribution_points, 0, 0);
                for (int i = 0, count = sk_DIST_POINT_num (distributionPoints); i < count; ++i) {
                    const DIST_POINT_NAME *distributionPoint = sk_DIST_POINT_value (distributionPoints, i)->distpoint;
                    if (distributionPoint->type == 0) {
                        for (int j = 0, count = sk_GENERAL_NAME_num (distributionPoint->name.fullname); j < count; ++j) {
                            const ASN1_IA5STRING *url =
                                sk_GENERAL_NAME_value (distributionPoint->name.fullname, j)->d.uniformResourceIdentifier;
                            crlDistributionPoints.push_back (
                                std::string (
                                    (const char *)ASN1_STRING_get0_data (url),
                                    ASN1_STRING_length (url)));
                        }
                    }
                    else if (distributionPoint->type == 1) {
                        const STACK_OF (X509_NAME_ENTRY) *relativeNames = distributionPoint->name.relativename;
                        for (int j = 0, count = sk_X509_NAME_ENTRY_num (relativeNames); j < count; ++j) {
                            const ASN1_STRING *url =
                                X509_NAME_ENTRY_get_data (sk_X509_NAME_ENTRY_value (relativeNames, j));
                            crlDistributionPoints.push_back (
                                std::string(
                                    (const char *)ASN1_STRING_get0_data (url),
                                    ASN1_STRING_length (url)));
                        }
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL X509_CRLPtr _LIB_THEKOGANS_CRYPTO_API
        LoadCRL (
                const std::string &path,
                util::ui32 format,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (!path.empty () && (format == FORMAT_DER || format == FORMAT_PEM)) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    X509_CRLPtr crl (format == FORMAT_DER ?
                        d2i_X509_CRL_bio (bio.get (), 0) :
                        PEM_read_bio_X509_CRL (bio.get (), 0, passwordCallback, userData));
                    if (crl.get () != 0) {
                        return crl;
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
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        SaveCRL (
                const std::string &path,
                X509_CRL *crl,
                util::ui32 format) {
            if (!path.empty () && crl != 0 && (format == FORMAT_DER || format == FORMAT_PEM)) {
                BIOPtr bio (BIO_new_file (path.c_str (), "w+"));
                if (bio.get () != 0 ||
                        (format == FORMAT_PEM ?
                            PEM_write_bio_X509_CRL (bio.get (), crl) :
                            i2d_X509_CRL_bio (bio.get (), crl)) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API
        CheckCRL (
                X509_CRL *crl,
                X509 *cert) {
            if (cert != 0 && crl != 0) {
                X509_REVOKED *entry = 0;
                X509_CRL_get0_by_cert (crl, &entry, cert);
                return entry != 0;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API
        TimeInsensitiveCompare (
                const void *buffer1,
                const void *buffer2,
                std::size_t length) {
            if (buffer1 != 0 && buffer2 != 0 && length > 0) {
                const util::ui8 *ptr1 = (const util::ui8 *)buffer1;
                const util::ui8 *ptr2 = (const util::ui8 *)buffer2;
                util::ui32 total = 0;
                while (length-- > 0) {
                    total += *ptr1++ ^ *ptr2++;
                }
                return total == 0;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::string _LIB_THEKOGANS_CRYPTO_API OTP (
                const void *key,
                std::size_t keyLength,
                const void *buffer,
                std::size_t bufferLength,
                std::size_t passwordLength,
                const EVP_MD *md) {
            if (key != 0 && keyLength > 0 &&
                    buffer != 0 && bufferLength > 0 && passwordLength <= 8 && md != 0) {
                util::ui8 hash[EVP_MAX_MD_SIZE];
                util::ui32 hashLength = 0;
                if (HMAC (md, key, (util::i32)keyLength, (const util::ui8 *)buffer,
                        (util::i32)bufferLength, hash, &hashLength) != 0) {
                    util::ui32 offset = hash[hashLength - 1] & 0xf;
                    util::ui32 code =
                        ((hash[offset] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8) |
                        (hash[offset + 3] & 0xff);
                    static const util::ui32 ModPower[] = {
                        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
                    };
                    code %= ModPower[passwordLength];
                    std::string password = util::FormatString ("%u", code);
                    while (password.size () < passwordLength) {
                        password = "0" + password;
                    }
                    return password;
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

        _LIB_THEKOGANS_CRYPTO_DECL std::string _LIB_THEKOGANS_CRYPTO_API OTP (
                const void *key,
                std::size_t keyLength,
                util::ui64 value,
                std::size_t passwordLength,
                const EVP_MD *md) {
            if (key != 0 && keyLength > 0 &&
                    passwordLength <= 8 && md != 0) {
                util::ui8 buffer[8];
                for (util::ui32 i = 8; i-- > 0;) {
                    buffer[i] = (util::ui8)(value & 0xff);
                    value >>= 8;
                }
                return OTP (key, keyLength, buffer, 8, passwordLength, md);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL util::Exception _LIB_THEKOGANS_CRYPTO_API
        CreateOpenSSLException (
                const char *file,
                const char *function,
                util::ui32 line,
                const char *buildTime,
                const char *message) {
            if (file != 0 && function != 0 && buildTime != 0 && message != 0) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = ERR_get_error ();
                char buffer[256];
                ERR_error_string_n (errorCode, buffer, sizeof (buffer));
                util::Exception exception (file, function, line, buildTime,
                    errorCode, util::FormatString ("[0x%x:%d - %s]%s",
                        errorCode, errorCode, buffer, message));
                while ((errorCode = ERR_get_error_line (&file, (util::i32 *)&line)) != 0) {
                    exception.NoteLocation (file, "", line, "");
                }
                return exception;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
