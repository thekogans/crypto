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
#include <regex>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include "thekogans/util/Flags.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        _LIB_THEKOGANS_CRYPTO_DECL const char * const DER_ENCODING = "DER";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const PEM_ENCODING = "PEM";

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
        void SSL_CTXDeleter::operator () (SSL_CTX *ctx) {
            if (ctx != 0) {
                SSL_CTX_free (ctx);
            }
        }

        void SSLDeleter::operator () (SSL *ssl) {
            if (ssl != 0) {
                SSL_free (ssl);
            }
        }

        void SSL_SESSIONDeleter::operator () (SSL_SESSION *session) {
            if (session != 0) {
                SSL_SESSION_free (session);
            }
        }

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK (SessionInfo, util::SpinLock)

        const char * const SessionInfo::TAG_SESSION_INFO =
            "SessionInfo";
        const char * const SessionInfo::ATTR_SERVER_NAME =
            "ServerName";
        const char * const SessionInfo::ATTR_RENEGOTIATION_FREQUENCY =
            "RenegotiationFrequency";
        const char * const SessionInfo::ATTR_BIDIRECTIONAL_SHUTDOWN =
            "BidirectionalShutdown";
        const char * const SessionInfo::ATTR_COUNT_TRANSFERED =
            "CountTransfered";

        const SessionInfo SessionInfo::Empty;

        SessionInfo::SessionInfo (const SessionInfo &sessionInfo) :
                serverName (sessionInfo.serverName),
                renegotiationFrequency (sessionInfo.renegotiationFrequency),
                bidirectionalShutdown (sessionInfo.bidirectionalShutdown),
                countTransfered (sessionInfo.countTransfered),
                session (sessionInfo.session.get ()) {
            if (session.get () != 0) {
            #if OPENSSL_VERSION_NUMBER < 0x10100000L
                CRYPTO_add (&session->references, 1, CRYPTO_LOCK_SSL_SESSION);
            #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                SSL_SESSION_up_ref (session.get ());
            #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
            }
        }

        SessionInfo &SessionInfo::operator = (
                const SessionInfo &sessionInfo) {
            if (&sessionInfo != this) {
                serverName = sessionInfo.serverName;
                renegotiationFrequency = sessionInfo.renegotiationFrequency;
                bidirectionalShutdown = sessionInfo.bidirectionalShutdown;
                countTransfered = sessionInfo.countTransfered;
                session.reset (sessionInfo.session.get ());
                if (session.get () != 0) {
                #if OPENSSL_VERSION_NUMBER < 0x10100000L
                    CRYPTO_add (&session->references, 1, CRYPTO_LOCK_SSL_SESSION);
                #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                    SSL_SESSION_up_ref (session.get ());
                #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
                }
            }
            return *this;
        }

        void SessionInfo::Parse (const pugi::xml_node &node) {
            serverName = util::Decodestring (node.attribute (ATTR_SERVER_NAME).value ());
            renegotiationFrequency = util::stringToui32 (node.attribute (ATTR_RENEGOTIATION_FREQUENCY).value ());
            bidirectionalShutdown = std::string (node.attribute (ATTR_BIDIRECTIONAL_SHUTDOWN).value ()) == util::XML_TRUE;
            countTransfered = util::stringToui32 (node.attribute (ATTR_COUNT_TRANSFERED).value ());
        }

        std::string SessionInfo::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            if (tagName != 0) {
                util::Attributes attributes;
                attributes.push_back (
                    util::Attribute (
                        ATTR_SERVER_NAME,
                        util::Encodestring (serverName)));
                attributes.push_back (
                    util::Attribute (
                        ATTR_RENEGOTIATION_FREQUENCY,
                        util::size_tTostring (renegotiationFrequency)));
                attributes.push_back (
                    util::Attribute (
                        ATTR_BIDIRECTIONAL_SHUTDOWN,
                        bidirectionalShutdown ? util::XML_TRUE : util::XML_FALSE));
                attributes.push_back (
                    util::Attribute (
                        ATTR_COUNT_TRANSFERED,
                        util::size_tTostring (countTransfered)));
                return util::OpenTag (indentationLevel, tagName, attributes, true, true);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
        GetCipherIVLength (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return EVP_CIPHER_iv_length (cipher);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
        GetCipherKeyLength (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return EVP_CIPHER_key_length (cipher);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL util::i32 _LIB_THEKOGANS_CRYPTO_API
        GetCipherMode (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return EVP_CIPHER_mode (cipher);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API
        IsCipherAEAD (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return util::Flags<unsigned long> (EVP_CIPHER_flags (cipher)).Test (
                    EVP_CIPH_FLAG_AEAD_CIPHER);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
        GetMDLength (const EVP_MD *md) {
            if (md != 0) {
                return (std::size_t)EVP_MD_size (md);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_RSA = "RSA";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_DSA = "DSA";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_DH = "DH";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_EC = "EC";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_HMAC = "HMAC";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_PKEY_CMAC = "CMAC";

        _LIB_THEKOGANS_CRYPTO_DECL const char * _LIB_THEKOGANS_CRYPTO_API
        EVP_PKEYtypeTostring (util::i32 type) {
            return type == EVP_PKEY_RSA ? OPENSSL_PKEY_RSA :
                type == EVP_PKEY_DSA ? OPENSSL_PKEY_DSA :
                type == EVP_PKEY_DH ? OPENSSL_PKEY_DH :
                type == EVP_PKEY_EC ? OPENSSL_PKEY_EC :
                type == EVP_PKEY_HMAC ? OPENSSL_PKEY_HMAC :
                type == EVP_PKEY_CMAC ? OPENSSL_PKEY_CMAC : "unknown";
        }

        _LIB_THEKOGANS_CRYPTO_DECL util::i32 _LIB_THEKOGANS_CRYPTO_API
        stringToEVP_PKEYtype (const char *type) {
            std::string strType (type);
            return strType == OPENSSL_PKEY_RSA ? EVP_PKEY_RSA :
                strType == OPENSSL_PKEY_DSA ? EVP_PKEY_DSA :
                strType == OPENSSL_PKEY_DH ? EVP_PKEY_DH:
                strType == OPENSSL_PKEY_EC ? EVP_PKEY_EC :
                strType == OPENSSL_PKEY_HMAC ? EVP_PKEY_HMAC :
                strType == OPENSSL_PKEY_CMAC ? EVP_PKEY_CMAC : EVP_PKEY_NONE;
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
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (!path.empty () && (encoding == DER_ENCODING || encoding == PEM_ENCODING)) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    X509_CRLPtr crl (encoding == DER_ENCODING ?
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
                X509_CRL *crl,
                const std::string &path,
                const std::string &encoding) {
            if (!path.empty () && crl != 0 && (encoding == DER_ENCODING || encoding == PEM_ENCODING)) {
                BIOPtr bio (BIO_new_file (path.c_str (), "w+"));
                if (bio.get () != 0 ||
                        (encoding == DER_ENCODING ?
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

        _LIB_THEKOGANS_CRYPTO_DECL X509Ptr _LIB_THEKOGANS_CRYPTO_API
        ParseCertificate (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    X509Ptr certificate (
                        d2i_X509 (0, (const util::ui8 **)&buffer, (long)length));
                    if (certificate.get () != 0) {
                        return certificate;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        X509Ptr certificate (
                            PEM_read_bio_X509 (bio.get (), 0, passwordCallback, userData));
                        if (certificate.get () != 0) {
                            return certificate;
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
        ParsePUBKEY (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    EVP_PKEYPtr key (
                        d2i_PUBKEY (0, (const util::ui8 **)&buffer, (long)length));
                    if (key.get () != 0) {
                        return key;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        EVP_PKEYPtr key (
                            PEM_read_bio_PUBKEY (bio.get (), 0, passwordCallback, userData));
                        if (key.get () != 0) {
                            return key;
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
        ParsePrivateKey (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    EVP_PKEYPtr key (d2i_AutoPrivateKey (0, (const util::ui8 **)&buffer, (long)length));
                    if (key.get () != 0) {
                        return key;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        EVP_PKEYPtr key (
                            PEM_read_bio_PrivateKey (bio.get (), 0, passwordCallback, userData));
                        if (key.get () != 0) {
                            return key;
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
        ParsePublicKey (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    {
                        const util::ui8 **ptr = (const util::ui8 **)&buffer;
                        // RSA is most common. Try it first.
                        RSAPtr rsa (d2i_RSAPublicKey (0, ptr, (long)length));
                        if (rsa.get () != 0) {
                            EVP_PKEYPtr key (EVP_PKEY_new ());
                            if (key.get () != 0 && EVP_PKEY_assign_RSA (key.get (), rsa.get ()) == 1) {
                                rsa.release ();
                                return key;
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                    }
                    {
                        const util::ui8 **ptr = (const util::ui8 **)&buffer;
                        // If not RSA, try DSA.
                        DSAPtr dsa (d2i_DSAPublicKey (0, ptr, (long)length));
                        if (dsa.get () != 0) {
                            EVP_PKEYPtr key (EVP_PKEY_new ());
                            if (key.get () != 0 && EVP_PKEY_assign_DSA (key.get (), dsa.get ()) == 1) {
                                dsa.release ();
                                return key;
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                    }
                    {
                        const util::ui8 **ptr = (const util::ui8 **)&buffer;
                        // Finally, try an Elliptic curve public key.
                        EC_KEYPtr ec (o2i_ECPublicKey (0, ptr, (long)length));
                        if (ec.get () != 0) {
                            EVP_PKEYPtr key (EVP_PKEY_new ());
                            if (key.get () != 0 && EVP_PKEY_assign_EC_KEY (key.get (), ec.get ()) == 1) {
                                ec.release ();
                                return key;
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                    }
                    // None of the above? Throw.
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to determine public key type. (Tried: %s, %s, %s)",
                        OPENSSL_PKEY_RSA,
                        OPENSSL_PKEY_DSA,
                        OPENSSL_PKEY_EC);
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        RSAPtr rsa (
                            PEM_read_bio_RSAPublicKey (
                                bio.get (),
                                0,
                                passwordCallback,
                                userData));
                        if (rsa.get () != 0) {
                            EVP_PKEYPtr key (EVP_PKEY_new ());
                            if (key.get () != 0 &&
                                    EVP_PKEY_assign_RSA (key.get (), rsa.get ()) == 1) {
                                rsa.release ();
                                return key;
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
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL DHPtr _LIB_THEKOGANS_CRYPTO_API
        ParseDHParams (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    DHPtr dhParams (
                        d2i_DHparams (0, (const util::ui8 **)&buffer, (long)length));
                    if (dhParams.get () != 0) {
                        return dhParams;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        DHPtr dh (
                            PEM_read_bio_DHparams (bio.get (), 0, passwordCallback, userData));
                        if (dh.get () != 0) {
                            return dh;
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
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL DSAPtr _LIB_THEKOGANS_CRYPTO_API
        ParseDSAParams (
                const void *buffer,
                std::size_t length,
                const std::string &encoding,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (buffer != 0 && length > 0) {
                if (encoding == DER_ENCODING) {
                    DSAPtr dsaParams (
                        d2i_DSAparams (0, (const util::ui8 **)&buffer, (long)length));
                    if (dsaParams.get () != 0) {
                        return dsaParams;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (encoding == PEM_ENCODING) {
                    // NOTE: I hate casting away constness, but thankfully,
                    // in this case it's harmless. Even though BIO_new_mem_buf
                    // wants an util::ui8 *, it marks the bio as read only,
                    // and therefore will not alter the buffer.
                    BIOPtr bio (BIO_new_mem_buf ((util::ui8 *)buffer, (int)length));
                    if (bio.get () != 0) {
                        DSAPtr dsa (
                            PEM_read_bio_DSAparams (bio.get (), 0, passwordCallback, userData));
                        if (dsa.get () != 0) {
                            return dsa;
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
                for (std::size_t i = 8; i-- > 0;) {
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

        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_TLS_1_0 = "1.0";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_TLS_1_1 = "1.1";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_TLS_1_2 = "1.2";

        _LIB_THEKOGANS_CRYPTO_DECL const SSL_METHOD * _LIB_THEKOGANS_CRYPTO_API
        GetTLSMethod (const std::string &version) {
            if (version == OPENSSL_TLS_1_0) {
                return TLSv1_method ();
            }
            if (version == OPENSSL_TLS_1_1) {
                return TLSv1_1_method ();
            }
            if (version == OPENSSL_TLS_1_2) {
                return TLSv1_2_method ();
            }
            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
        }

        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_DTLS_1_0 = "1.0";
        _LIB_THEKOGANS_CRYPTO_DECL const char * const OPENSSL_DTLS_1_2 = "1.2";

        _LIB_THEKOGANS_CRYPTO_DECL const SSL_METHOD * _LIB_THEKOGANS_CRYPTO_API
        GetDTLSMethod (const std::string &version) {
            if (version == OPENSSL_DTLS_1_0) {
                return DTLSv1_method ();
            }
            if (version == OPENSSL_DTLS_1_2) {
                return DTLSv1_2_method ();
            }
            THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
        }

        _LIB_THEKOGANS_CRYPTO_DECL int
        VerifyCallback (
                int ok,
                X509_STORE_CTX *store) {
            if (!ok) {
                int depth = X509_STORE_CTX_get_error_depth (store);
                int error = X509_STORE_CTX_get_error (store);
                const int MAX_NAME_LENGTH = 256;
                char issuer[MAX_NAME_LENGTH] = {0};
                char subject[MAX_NAME_LENGTH] = {0};
                X509 *cert = X509_STORE_CTX_get_current_cert (store);
                if (cert != 0) {
                    X509_NAME_oneline (X509_get_issuer_name (cert), issuer, sizeof (issuer));
                    X509_NAME_oneline (X509_get_subject_name (cert), subject, sizeof (subject));
                }
                else {
                    util::CopyString (issuer, MAX_NAME_LENGTH, "Unknown issuer.");
                    util::CopyString (subject, MAX_NAME_LENGTH, "Unknown subject.");
                }
                const char *message = X509_verify_cert_error_string (error);
                THEKOGANS_UTIL_LOG_SUBSYSTEM_ERROR (
                    THEKOGANS_CRYPTO,
                    "%s",
                    util::FormatString (
                        "Error with certificate at depth: %i\n"
                        "  issuer = %s\n"
                        "  subject = %s\n"
                        "  error %i:%s\n",
                        depth, issuer, subject, error,
                        message != 0 ? message : "Unknown error.").c_str ());
            }
            return ok;
        }

        namespace {
            bool CompareServerName (
                    const std::string &serverName,
                    const std::string &certificateName) {
                if (certificateName.find_first_of ('*') != std::string::npos) {
                    // This is a wildcard certificate. Do a regex match.
                    std::string patern;
                    for (std::size_t i = 0, count = certificateName.size (); i < count; ++i) {
                        if (certificateName[i] == '*') {
                            patern += ".+";
                        }
                        else if (certificateName[i] == '.') {
                            patern += "\\.";
                        }
                        else {
                            patern += certificateName[i];
                        }
                    }
                    return std::regex_match (serverName, std::regex (patern));
                }
                return util::StringCompareIgnoreCase (serverName.c_str (), certificateName.c_str ()) == 0;
            }

            bool CheckSubjectName (
                    X509 *cert,
                    const std::string &serverName) {
                char commonName[256] = {0};
                {
                    X509_NAME *subjectName = X509_get_subject_name (cert);
                    if (subjectName != 0) {
                        X509_NAME_get_text_by_NID (
                            subjectName, NID_commonName, commonName, sizeof (commonName));
                    }
                }
                return CompareServerName (serverName, commonName);
            }

            inline std::string GetExtensionName (X509_EXTENSION *extension) {
                return std::string (
                    (const char *)OBJ_nid2sn (
                        OBJ_obj2nid (X509_EXTENSION_get_object (extension))));
            }

            bool CheckSubjectAltName (
                    X509 *cert,
                    const std::string &serverName) {
                for (int i = 0, count = X509_get_ext_count (cert); i < count; ++i) {
                    X509_EXTENSION *extension = X509_get_ext (cert, i);
                    if (GetExtensionName (extension) == "subjectAltName") {
                        const X509V3_EXT_METHOD *method = X509V3_EXT_get (extension);
                        if (method != 0) {
                            void *extensionData = 0;
                        #if OPENSSL_VERSION_NUMBER < 0x10100000L
                            const void *data = extension->value->data;
                        #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                            const ASN1_OCTET_STRING *data = X509_EXTENSION_get_data (extension);
                        #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
                            if (method->it != 0) {
                                extensionData = ASN1_item_d2i (0,
                                #if OPENSSL_VERSION_NUMBER < 0x10100000L
                                    (const util::ui8 **)&data,
                                    extension->value->length,
                                #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                                    (const util::ui8 **)&data->data,
                                    data->length,
                                #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
                                    ASN1_ITEM_ptr (method->it));
                            }
                            else {
                                extensionData = method->d2i (0,
                                #if OPENSSL_VERSION_NUMBER < 0x10100000L
                                    (const util::ui8 **)&data,
                                    extension->value->length);
                                #else // OPENSSL_VERSION_NUMBER < 0x10100000L
                                    (const util::ui8 **)&data->data,
                                    data->length);
                                #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
                            }
                            STACK_OF (CONF_VALUE) *nameValues = method->i2v (method, extensionData, 0);
                            if (nameValues != 0) {
                                for (int j = 0, count = sk_CONF_VALUE_num (nameValues); j < count; ++j) {
                                    CONF_VALUE *nameValue = sk_CONF_VALUE_value (nameValues, j);
                                    if (nameValue != 0) {
                                        if (std::string ("DNS") == nameValue->name &&
                                                CompareServerName (serverName, nameValue->value)) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return false;
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL int _LIB_THEKOGANS_CRYPTO_API
        PostConnectionCheck (
                SSL *ssl,
                const std::string &serverName) {
            crypto::X509Ptr cert (SSL_get_peer_certificate (ssl));
            return cert.get () != 0 &&
                (CheckSubjectName (cert.get (), serverName) ||
                    CheckSubjectAltName (cert.get (), serverName)) ?
                X509_V_OK : X509_V_ERR_APPLICATION_VERIFICATION;
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        LoadCACertificates (
                SSL_CTX *ctx,
                const std::list<std::string> &caCertificates,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !caCertificates.empty ()) {
                crypto::X509_STOREPtr newStore;
                X509_STORE *store = SSL_CTX_get_cert_store (ctx);
                if (store == 0) {
                    newStore.reset (X509_STORE_new ());
                    if (newStore.get () != 0) {
                        store = newStore.get ();
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                for (std::list<std::string>::const_iterator
                        it = caCertificates.begin (),
                        end = caCertificates.end (); it != end; ++it) {
                    if (X509_STORE_add_cert (store,
                            crypto::ParseCertificate (
                                it->data (),
                                it->size (),
                                crypto::PEM_ENCODING,
                                passwordCallback,
                                userData).get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                if (newStore.get () != 0) {
                    SSL_CTX_set_cert_store (ctx, newStore.release ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        LoadCertificateChain (
                SSL_CTX *ctx,
                const std::list<std::string> &certificateChain,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !certificateChain.empty ()) {
                std::list<std::string>::const_iterator it = certificateChain.begin ();
                const std::string &certificate = *it++;
                if (SSL_CTX_use_certificate (ctx,
                        crypto::ParseCertificate (
                            certificate.data (),
                            certificate.size (),
                            crypto::PEM_ENCODING,
                            passwordCallback,
                            userData).get ()) == 1) {
                    SSL_CTX_clear_chain_certs (ctx);
                    for (std::list<std::string>::const_iterator
                            end = certificateChain.end (); it != end; ++it) {
                        const std::string &certificate = *it;
                        if (SSL_CTX_add1_chain_cert (ctx,
                                crypto::ParseCertificate (
                                    certificate.data (),
                                    certificate.size (),
                                    crypto::PEM_ENCODING,
                                    passwordCallback,
                                    userData).get ()) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
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
        LoadPrivateKey (
                SSL_CTX *ctx,
                const std::string &privateKey,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0 && !privateKey.empty ()) {
                if (SSL_CTX_use_PrivateKey (ctx,
                        crypto::ParsePrivateKey (
                            privateKey.data (),
                            privateKey.size (),
                            crypto::PEM_ENCODING,
                            passwordCallback,
                            userData).get ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        LoadCipherList (
                SSL_CTX *ctx,
                const std::string &cipherList) {
            std::string trimmedCipherList = util::TrimSpaces (cipherList.c_str ());
            if (ctx != 0 && !trimmedCipherList.empty ()) {
                if (SSL_CTX_set_cipher_list (ctx, trimmedCipherList.c_str ()) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        LoadDHParams (
                SSL_CTX *ctx,
                const std::string &dhParams,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0) {
                // DH params are optional.
                if (!dhParams.empty ()) {
                    SSL_CTX_set_options (ctx, SSL_CTX_get_options (ctx) | SSL_OP_SINGLE_DH_USE);
                    if (SSL_CTX_set_tmp_dh (ctx,
                            crypto::ParseDHParams (
                                dhParams.data (),
                                dhParams.size (),
                                crypto::PEM_ENCODING,
                                passwordCallback,
                                userData).get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
        LoadECDHParams (
                SSL_CTX *ctx,
                const std::string &ecdhParamsType,
                const std::string &ecdhParams,
                pem_password_cb *passwordCallback,
                void *userData) {
            if (ctx != 0) {
                // ECDH params are optional.
                if (ecdhParamsType == "auto") {
                    SSL_CTX_set_ecdh_auto (ctx, 1);
                }
                else if (ecdhParamsType == "curve") {
                    crypto::EC_KEYPtr ecdh (
                        EC_KEY_new_by_curve_name (OBJ_sn2nid (ecdhParams.c_str ())));
                    if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (ecdhParamsType == crypto::PEM_ENCODING) {
                    crypto::EVP_PKEYPtr key = crypto::ParsePUBKEY (
                        ecdhParams.data (),
                        ecdhParams.size (),
                        crypto::PEM_ENCODING,
                        passwordCallback,
                        userData);
                    if (key.get () != 0) {
                        crypto::EC_KEYPtr ecdh (EVP_PKEY_get1_EC_KEY (key.get ()));
                        if (ecdh.get () == 0 || SSL_CTX_set_tmp_ecdh (ctx, ecdh.get ()) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
