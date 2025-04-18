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

#if !defined (__thekogans_crypto_OpenSSLUtils_h)
#define __thekogans_crypto_OpenSSLUtils_h

#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "pugixml/pugixml.hpp"
#include "thekogans/util/Types.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \brief
        /// "DER"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const DER_ENCODING;
        /// \brief
        /// "PEM"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const PEM_ENCODING;

        /// \struct BN_CTXDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for BN_CTX.
        struct _LIB_THEKOGANS_CRYPTO_DECL BN_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ctx BN_CTX to delete.
            void operator () (BN_CTX *ctx);
        };
        /// \brief
        /// Alias for std::unique_ptr<BN_CTX, BN_CTXDeleter>.
        using BN_CTXPtr = std::unique_ptr<BN_CTX, BN_CTXDeleter>;

        /// \struct BIGNUMDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for BIGNUM.
        struct _LIB_THEKOGANS_CRYPTO_DECL BIGNUMDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key BIGNUM to delete.
            void operator () (BIGNUM *bn);
        };
        /// \brief
        /// Alias for std::unique_ptr<BIGNUM, BIGNUMDeleter>.
        using BIGNUMPtr = std::unique_ptr<BIGNUM, BIGNUMDeleter>;

        /// \struct EVP_PKEY_CTXDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_PKEY_CTX.
        struct _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEY_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ctx EVP_PKEY_CTX to delete.
            void operator () (EVP_PKEY_CTX *ctx);
        };
        /// \brief
        /// Alias for std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>.
        using EVP_PKEY_CTXPtr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTXDeleter>;

        /// \struct EVP_PKEYDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_PKEY.
        struct _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_PKEY to delete.
            void operator () (EVP_PKEY *key);
        };
        /// \brief
        /// Alias for std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>.
        using EVP_PKEYPtr = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;

        /// \struct EC_GROUPDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EC_GROUP.
        struct _LIB_THEKOGANS_CRYPTO_DECL EC_GROUPDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] group EC_GROUP to delete.
            void operator () (EC_GROUP *group);
        };
        /// \brief
        /// Alias for std::unique_ptr<EC_GROUP, EC_GROUPDeleter>.
        using EC_GROUPPtr = std::unique_ptr<EC_GROUP, EC_GROUPDeleter>;

        /// \struct EC_POINTDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EC_POINT.
        struct _LIB_THEKOGANS_CRYPTO_DECL EC_POINTDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] point EC_POINT to delete.
            void operator () (EC_POINT *point);
        };
        /// \brief
        /// Alias for std::unique_ptr<EC_POINT, EC_POINTDeleter>.
        using EC_POINTPtr = std::unique_ptr<EC_POINT, EC_POINTDeleter>;

        /// \struct EC_KEYDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EC_KEY.
        struct _LIB_THEKOGANS_CRYPTO_DECL EC_KEYDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EC_KEY to delete.
            void operator () (EC_KEY *key);
        };
        /// \brief
        /// Alias for std::unique_ptr<EC_KEY, EC_KEYDeleter>.
        using EC_KEYPtr = std::unique_ptr<EC_KEY, EC_KEYDeleter>;

        /// \struct EVP_CIPHER_CTXDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_CIPHER_CTX.
        struct _LIB_THEKOGANS_CRYPTO_DECL EVP_CIPHER_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_CIPHER_CTX to delete.
            void operator () (EVP_CIPHER_CTX *ctx);
        };
        /// \brief
        /// Alias for std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTXDeleter>.
        using EVP_CIPHER_CTXPtr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTXDeleter> ;

        /// \struct EVP_MD_CTXDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for EVP_MD_CTX.
        struct _LIB_THEKOGANS_CRYPTO_DECL EVP_MD_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] key EVP_MD_CTX to delete.
            void operator () (EVP_MD_CTX *ctx);
        };
        /// \brief
        /// Alias for std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter>.
        using EVP_MD_CTXPtr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTXDeleter>;

        /// \struct BIODeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for BIO.
        struct _LIB_THEKOGANS_CRYPTO_DECL BIODeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] bio BIO to delete.
            void operator () (BIO *bio);
        };
        /// \brief
        /// Alias for std::unique_ptr<BIO, BIODeleter>.
        using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

        /// \struct X509_STOREDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for X509_STORE.
        struct _LIB_THEKOGANS_CRYPTO_DECL X509_STOREDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] store X509_STORE to delete.
            void operator () (X509_STORE *store);
        };
        /// \brief
        /// Alias for std::unique_ptr<X509_STORE, X509_STOREDeleter>.
        using X509_STOREPtr = std::unique_ptr<X509_STORE, X509_STOREDeleter>;

        /// \struct X509_CRLDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for X509_CRL.
        struct _LIB_THEKOGANS_CRYPTO_DECL X509_CRLDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] crl X509_CRL to delete.
            void operator () (X509_CRL *crl);
        };
        /// \brief
        /// Alias for std::unique_ptr<X509_CRL, X509_CRLDeleter>.
        using X509_CRLPtr = std::unique_ptr<X509_CRL, X509_CRLDeleter>;

        /// \struct X509Deleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for X509.
        struct _LIB_THEKOGANS_CRYPTO_DECL X509Deleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] x509 X509 to delete.
            void operator () (X509 *x509);
        };
        /// \brief
        /// Alias for std::unique_ptr<X509, X509Deleter>.
        using X509Ptr = std::unique_ptr<X509, X509Deleter>;

        /// \struct DHDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for DH.
        struct _LIB_THEKOGANS_CRYPTO_DECL DHDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] dh DH to delete.
            void operator () (DH *dh);
        };
        /// \brief
        /// Alias for std::unique_ptr<DH, DHDeleter>.
        using DHPtr = std::unique_ptr<DH, DHDeleter>;

        /// \struct DSADeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for DSA.
        struct _LIB_THEKOGANS_CRYPTO_DECL DSADeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] dsa DSA to delete.
            void operator () (DSA *dsa);
        };
        /// \brief
        /// Alias for std::unique_ptr<DSA, DSADeleter>.
        using DSAPtr = std::unique_ptr<DSA, DSADeleter>;

        /// \struct RSADeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for RSA.
        struct _LIB_THEKOGANS_CRYPTO_DECL RSADeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] rsa RSA to delete.
            void operator () (RSA *rsa);
        };
        /// \brief
        /// Alias for std::unique_ptr<RSA, RSADeleter>.
        using RSAPtr = std::unique_ptr<RSA, RSADeleter>;

        /// \struct SSL_CTXDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL_CTX.
        struct _LIB_THEKOGANS_CRYPTO_DECL SSL_CTXDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ctx SSL_CTX to delete.
            void operator () (SSL_CTX *ctx);
        };
        /// \brief
        /// Alias for std::unique_ptr<SSL_CTX, SSL_CTXDeleter>.
        using SSL_CTXPtr = std::unique_ptr<SSL_CTX, SSL_CTXDeleter>;

        /// \struct SSLDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL.
        struct _LIB_THEKOGANS_CRYPTO_DECL SSLDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] ssl SSL to delete.
            void operator () (SSL *ssl);
        };
        /// \brief
        /// Alias for std::unique_ptr<SSL, SSLDeleter>.
        using SSLPtr = std::unique_ptr<SSL, SSLDeleter>;

        /// \struct SSL_SESSIONDeleter OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Custom deleter for SSL_SESSION.
        struct _LIB_THEKOGANS_CRYPTO_DECL SSL_SESSIONDeleter {
            /// \brief
            /// Called by unique_ptr::~unique_ptr.
            /// \param[in] session SSL_SESSION to delete.
            void operator () (SSL_SESSION *session);
        };
        /// \brief
        /// Alias for std::unique_ptr<SSL_SESSION, SSL_SESSIONDeleter>.
        using SSL_SESSIONPtr = std::unique_ptr<SSL_SESSION, SSL_SESSIONDeleter>;

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        /// \struct CipherContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct CipherContext : public EVP_CIPHER_CTX {
            /// \brief
            /// ctor.
            CipherContext () {
                EVP_CIPHER_CTX_init (this);
            }
            /// \brief
            /// dtor.
            ~CipherContext () {
                EVP_CIPHER_CTX_cleanup (this);
            }
        };

        /// \struct MDContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct MDContext : public EVP_MD_CTX {
            /// \brief
            /// ctor.
            MDContext () {
                EVP_MD_CTX_init (this);
            }
            /// \brief
            /// dtor.
            ~MDContext () {
                EVP_MD_CTX_cleanup (this);
            }
        };

        /// \struct HMACContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct HMACContext : public HMAC_CTX {
            /// \brief
            /// ctor.
            HMACContext () {
                HMAC_CTX_init (this);
            }
            /// \brief
            /// dtor.
            ~HMACContext () {
                HMAC_CTX_cleanup (this);
            }
        };
    #else // OPENSSL_VERSION_NUMBER < 0x10100000L
        /// \struct CipherContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct CipherContext {
            /// \brief
            /// OpenSSL cipher context.
            EVP_CIPHER_CTX *ctx;

            /// \brief
            /// ctor.
            CipherContext () :
                ctx (EVP_CIPHER_CTX_new ()) {}
            /// \brief
            /// dtor.
            ~CipherContext () {
                EVP_CIPHER_CTX_free (ctx);
            }

            /// \brief
            /// Address of operator.
            /// \return EVP_CIPHER_CTX *.
            EVP_CIPHER_CTX *operator & () const {
                return ctx;
            }
        };

        /// \struct MDContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct MDContext {
            /// \brief
            /// OpenSSL message digest context.
            EVP_MD_CTX *ctx;

            /// \brief
            /// ctor.
            MDContext () :
                ctx (EVP_MD_CTX_new ()) {}
            /// \brief
            /// dtor.
            ~MDContext () {
                EVP_MD_CTX_free (ctx);
            }

            /// \brief
            /// Address of operator.
            /// \return EVP_MD_CTX *.
            EVP_MD_CTX *operator & () const {
                return ctx;
            }
        };

        /// \struct HMACContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct HMACContext {
            /// \brief
            /// OpenSSL message digest context.
            HMAC_CTX *ctx;

            /// \brief
            /// ctor.
            HMACContext () :
                ctx (HMAC_CTX_new ()) {}
            /// \brief
            /// dtor.
            ~HMACContext () {
                HMAC_CTX_free (ctx);
            }

            /// \brief
            /// Address of operator.
            /// \return HMAC_CTX *.
            HMAC_CTX *operator & () const {
                return ctx;
            }
        };
    #endif // OPENSSL_VERSION_NUMBER < 0x10100000L

        /// \struct CMACContext OpenSSLUtils.h thekogans/crypto/OpenSSLUtils.h
        ///
        /// \brief
        /// Adds ctor/dtor to OpenSSL's pods to provide exception safety.
        struct CMACContext {
            /// \brief
            /// OpenSSL message digest context.
            CMAC_CTX *ctx;

            /// \brief
            /// ctor.
            CMACContext () :
                ctx (CMAC_CTX_new ()) {}
            /// \brief
            /// dtor.
            ~CMACContext () {
                CMAC_CTX_free (ctx);
            }

            /// \brief
            /// Address of operator.
            /// \return CMAC_CTX *.
            CMAC_CTX *operator & () const {
                return ctx;
            }
        };

        /// \brief
        /// The following utilities aid in performing thekogans.net style of TLS.
        /// This style uses an xml configuration file to store certificates and
        /// other parameters. Please see examples/secure[tcp | udp]echo (specifically
        /// the mkcerts-[dsa | rsa] scripts) to learn how to do that.

        /// \struct SessionInfo OpenSSLInit.h thekogans/crypto/OpenSSLInit.h
        ///
        /// \brief
        /// SessionInfo stores extended session info. Info that would
        /// not otherwise fit in to SSL_CTX. It's also used to retrieve
        /// the currently negotiated session state \see{SecureTCPSocket::GetSessionInfo}
        /// to be later passed back in to SecureTCPSocket::SessionConnect
        /// to attempt session resumption.
        struct _LIB_THEKOGANS_CRYPTO_DECL SessionInfo : public util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (SessionInfo)

            /// \brief
            /// SessionInfo has a private heap to help with memory
            /// management, performance, and global heap fragmentation.
            THEKOGANS_UTIL_DECLARE_STD_ALLOCATOR_FUNCTIONS

            /// \brief
            /// Default renegotiation frequency (in bytes).
            /// NOTE: This value aggregates both reads ands writes.
            static const std::size_t DEFAULT_RENEGOTIATION_FREQUENCY = util::UI32_MAX;

            /// \brief
            /// "SessionInfo"
            static const char * const TAG_SESSION_INFO;
            /// \brief
            /// "ServerName"
            static const char * const ATTR_SERVER_NAME;
            /// \brief
            /// "RenegotiationFrequency"
            static const char * const ATTR_RENEGOTIATION_FREQUENCY;
            /// \brief
            /// "BidirectionalShutdown"
            static const char * const ATTR_BIDIRECTIONAL_SHUTDOWN;
            /// \brief
            /// "CountTransfered"
            static const char * const ATTR_COUNT_TRANSFERED;

            /// \brief
            /// On client it's SNI and the name to verify post connecton.
            std::string serverName;
            /// \brief
            /// How many bytes to transfer before initiating
            /// a session renegotiation.
            std::size_t renegotiationFrequency;
            /// \brief
            /// If true, perform bidirectional shutdown.
            bool bidirectionalShutdown;
            /// \brief
            /// Count of bytes transfered (both read and write).
            /// When it reaches renegotiationFrequency, a rehandshake
            /// will be initiated and the counter will be reset.
            std::size_t countTransfered;
            /// \brief
            /// Active session.
            SSL_SESSIONPtr session;

            /// \brief
            /// ctor.
            /// \param[in] serverName_ Server name to validate..
            /// \param[in] renegotiationFrequency_ How many bytes to
            /// transfer before initiating a session renegotiation.
            /// \param[in] bidirectionalShutdown_ If true, perform
            /// bidirectional shutdown.
            /// \param[in] countTransfered_ Counter of bytes
            /// transfered (both read and write).
            SessionInfo (
                const std::string &serverName_ = std::string (),
                std::size_t renegotiationFrequency_ = DEFAULT_RENEGOTIATION_FREQUENCY,
                bool bidirectionalShutdown_ = true,
                std::size_t countTransfered_ = 0) :
                serverName (serverName_),
                renegotiationFrequency (renegotiationFrequency_),
                bidirectionalShutdown (bidirectionalShutdown_),
                countTransfered (countTransfered_) {}
            /// \brief
            /// ctor.
            /// \param[in] node pugi::xml_node representing
            /// a SecureTCPSocket::SessionInfo.
            SessionInfo (const pugi::xml_node &node) :
                    renegotiationFrequency (DEFAULT_RENEGOTIATION_FREQUENCY),
                    bidirectionalShutdown (true),
                    countTransfered (0) {
                Parse (node);
            }
            /// \brief
            /// Copy ctor.
            /// \param[in] sessionInfo SessionInfo to copy.
            SessionInfo (const SessionInfo &sessionInfo);

            /// \brief
            /// Assignement operator.
            /// \param[in] sessionInfo SessionInfo to copy.
            /// \return *this.
            SessionInfo &operator = (const SessionInfo &sessionInfo);

            /// \brief
            /// Parse a node representing a SecureTCPSocket::SessionInfo:
            /// <tagName ServerName = ""
            ///          RenegotiationFrequency = ""
            ///          BidirectionalShutdown = ""
            ///          CountTransfered = ""/>
            /// \param[in] node pugi::xml_node representing
            /// a SecureTCPSocket::SessionInfo.
            void Parse (const pugi::xml_node &node);
            /// \brief
            /// Return a string representing the rest
            /// state of the SecureTCPSocket::SessionInfo.
            /// \param[in] indentationLevel Pretty print parameter.
            /// indents the tag with 4 * indentationLevel spaces.
            /// \param[in] tagName Tag name (default to "SessionInfo").
            /// \return String representing the rest state of the
            /// SecureTCPSocket::SessionInfo.
            std::string ToString (
                std::size_t indentationLevel = 0,
                const char *tagName = TAG_SESSION_INFO) const;
        };

        /// \brief
        /// Return the iv length for a given OpenSSL cipher.
        /// \param[in] cipher OpenSSL cipher object.
        /// \return IV length for a given cipher.
        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API GetCipherIVLength (
            const EVP_CIPHER *cipher = THEKOGANS_CRYPTO_DEFAULT_CIPHER);

        /// \brief
        /// Return the key length for a given OpenSSL cipher.
        /// \param[in] cipher OpenSSL cipher object.
        /// \return Key length for a given cipher.
        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API GetCipherKeyLength (
            const EVP_CIPHER *cipher = THEKOGANS_CRYPTO_DEFAULT_CIPHER);

        /// \brief
        /// Return the mode (EVP_CIPH_CBC_MODE or EVP_CIPH_GCM_MODE) for a given OpenSSL cipher.
        /// \param[in] cipher OpenSSL cipher object.
        /// \return EVP_CIPH_CBC_MODE or EVP_CIPH_GCM_MODE.
        _LIB_THEKOGANS_CRYPTO_DECL util::i32 _LIB_THEKOGANS_CRYPTO_API GetCipherMode (
            const EVP_CIPHER *cipher = THEKOGANS_CRYPTO_DEFAULT_CIPHER);

        /// \brief
        /// Return true if the given OpenSSL cipher supports Authenticated Encryption with
        /// Associated Data (AEAD).
        /// \param[in] cipher OpenSSL cipher object.
        /// \return true = AEAD cipher.
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API IsCipherAEAD (
            const EVP_CIPHER *cipher = THEKOGANS_CRYPTO_DEFAULT_CIPHER);

        /// \brief
        /// Return the length of the digest given an OpenSSL message digest object.
        /// \param[in] md OpenSSL message digest object.
        /// \return Length of the digest for the given OpenSSL message digest object.
        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API GetMDLength (
            const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD);

        /// \brief
        /// "RSA"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_RSA;
        /// \brief
        /// "DSA"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_DSA;
        /// \brief
        /// "DH"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_DH;
        /// \brief
        /// "EC"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_EC;
        /// \brief
        /// "HMAC"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_HMAC;
        /// \brief
        /// "CMAC"
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_PKEY_CMAC;

        /// \brief
        /// Convert OpenSSL EVP_PKEY key type to string.
        /// \param[in] type One of EVP_PKEY_RSA, EVP_PKEY_DSA, EVP_PKEY_DH,
        /// EVP_PKEY_EC, EVP_PKEY_HMAC or EVP_PKEY_CMAC to "RSA", "DSA", "DH",
        /// "EC", "HMAC" or "CMAC".
        /// \return "RSA", "DSA", "DH", "EC", "HMAC" or "CMAC".
        _LIB_THEKOGANS_CRYPTO_DECL const char * _LIB_THEKOGANS_CRYPTO_API
            EVP_PKEYtypeTostring (util::i32 type);
        /// \brief
        /// Convert string to OpenSSL EVP_PKEY key type.
        /// \param[in] type One of "RSA", "DSA", "DH",
        /// "EC", "HMAC" or "CMAC" to EVP_PKEY_RSA, EVP_PKEY_DSA, EVP_PKEY_DH,
        /// EVP_PKEY_EC, EVP_PKEY_HMAC or EVP_PKEY_CMAC.
        /// \return EVP_PKEY_RSA, EVP_PKEY_DSA, EVP_PKEY_DH,
        /// EVP_PKEY_EC, EVP_PKEY_HMAC or EVP_PKEY_CMAC.
        _LIB_THEKOGANS_CRYPTO_DECL util::i32 _LIB_THEKOGANS_CRYPTO_API
            stringToEVP_PKEYtype (const char *type);

        /// \brief
        /// Create a BIGNUMPtr and initialize it to a given value.
        /// \param[in] value Value to initialize the BIGNUM to.
        /// \return BIGNUMPtr initialized to a given value.
        _LIB_THEKOGANS_CRYPTO_DECL BIGNUMPtr _LIB_THEKOGANS_CRYPTO_API
            BIGNUMFromui32 (util::ui32 value);

        /// \brief
        /// Get the list of certificate revocation lists (CRL) distribution
        /// points embedded in a given certificate.
        /// \param[in] cert Certificate containing the list of CRL distribution points.
        /// \param[out] crlDistributionPoints Extracted CRL distribution points.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            GetCRLDistributionPoints (
                X509 *cert,
                std::vector<std::string> &crlDistributionPoints);
        /// \brief
        /// Load a DER or PEM encoded CRL from a file.
        /// \param[in] path Path to CRL file.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
        /// will interpret the userData as a NULL terminated password.
        /// \return X509_CRLPtr containing the parsed CRL.
        _LIB_THEKOGANS_CRYPTO_DECL X509_CRLPtr _LIB_THEKOGANS_CRYPTO_API
            LoadCRL (
                const std::string &path,
                const std::string encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Save the given CRL to a file using the given encodong.
        /// \param[in] crl CRL to save.
        /// \param[in] path Path to CRL file.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            SaveCRL (
                X509_CRL *crl,
                const std::string &path,
                const std::string encoding = DER_ENCODING);
        /// \brief
        /// Check a given certificate (X509) against the given CRL.
        /// \param[in] crl CRL to check against.
        /// \param[in] cert Certificate to check.
        /// \return true = The given CRL contains the given certificate (revoked).
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API
            CheckCRL (
                X509_CRL *crl,
                X509 *cert);

        /// \brief
        /// Parse a DER or PEM encoded certificate.
        /// \param[in] buffer Buffer containing the encoded certificate.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed certificate.
        _LIB_THEKOGANS_CRYPTO_DECL X509Ptr _LIB_THEKOGANS_CRYPTO_API
            ParseCertificate (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a DER or PEM encoded PUBKEY public key.
        /// \param[in] buffer Buffer containing the encoded PUBKEY public key.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed public key.
        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
            ParsePUBKEY (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a DER or PEM encoded private key.
        /// \param[in] buffer Buffer containing the encoded private key.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed private key.
        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
            ParsePrivateKey (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a DER or PEM encoded public key.
        /// \param[in] buffer Buffer containing the encoded public key.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// NOTE: If the encoding is PEM_ENCODING, key type must be OPENSSL_PKEY_RSA.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed public key.
        _LIB_THEKOGANS_CRYPTO_DECL EVP_PKEYPtr _LIB_THEKOGANS_CRYPTO_API
            ParsePublicKey (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a DER or PEM encoded DH parameters.
        /// \param[in] buffer Buffer containing the encoded DH parameters.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed DH parameters.
        _LIB_THEKOGANS_CRYPTO_DECL DHPtr _LIB_THEKOGANS_CRYPTO_API
            ParseDHParams (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Parse a DER or PEM encoded DSA parameters.
        /// \param[in] buffer Buffer containing the encoded DSA parameters.
        /// \param[in] length Length of buffer.
        /// \param[in] encoding DER_ENCODING or PEM_ENCODING.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        /// \return Parsed DSA parameters.
        _LIB_THEKOGANS_CRYPTO_DECL DSAPtr _LIB_THEKOGANS_CRYPTO_API
            ParseDSAParams (
                const void *buffer,
                std::size_t length,
                const std::string &encoding = DER_ENCODING,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);

        /// \brief
        /// Perform time insensitive compare on the given buffers.
        /// \param[in] buffer1 First buffer to compare.
        /// \param[in] buffer2 Second buffer to compare.
        /// \param[in] length Length of both buffers.
        /// \return true = identical, false = different.
        _LIB_THEKOGANS_CRYPTO_DECL bool _LIB_THEKOGANS_CRYPTO_API
            TimeInsensitiveCompare (
                const void *buffer1,
                const void *buffer2,
                std::size_t length);

        /// \brief
        /// General purpose One Time Password generator.
        /// \param[in] key Key to use with HMAC.
        /// \param[in] keyLength Key length.
        /// \param[in] buffer Data to hash.
        /// \param[in] bufferLength Buffer length.
        /// \param[in] passwordLength Password length.
        /// \param[in] md Message digest.
        /// \return One Time Password.
        /// NOTE: All passwords returned by OTP are six digits long.
        _LIB_THEKOGANS_CRYPTO_DECL std::string _LIB_THEKOGANS_CRYPTO_API OTP (
            const void *key,
            std::size_t keyLength,
            const void *buffer,
            std::size_t bufferLength,
            std::size_t passwordLength = 6,
            const EVP_MD *md = EVP_sha1 ());
        /// \brief
        /// [H | T] One Time Password generator. By default, uses the
        /// current time (TOTP RFC 6238) with a 30 second validity window.
        /// Pass a monotonically increasing counter to perform HOTP
        /// described in RFC 4226.
        /// \param[in] key Key to use with HMAC.
        /// \param[in] keyLength Key length.
        /// \param[in] value Value to hash.
        /// \param[in] passwordLength Password length.
        /// \param[in] md Message digest.
        /// \return One Time Password.
        _LIB_THEKOGANS_CRYPTO_DECL std::string _LIB_THEKOGANS_CRYPTO_API OTP (
            const void *key,
            std::size_t keyLength,
            util::ui64 value = time (0) / 30,
            std::size_t passwordLength = 6,
            const EVP_MD *md = EVP_sha1 ());

        /// \brief
        /// Maximum TLS record length.
        const std::size_t TLS_MAX_RECORD_LENGTH = 16384;

        /// \brief
        /// TLS version 1.0
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_TLS_1_0;
        /// \brief
        /// TLS version 1.1
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_TLS_1_1;
        /// \brief
        /// TLS version 1.2
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_TLS_1_2;
        /// \brief
        /// Given a string representing a version, return the
        /// corresponding TLS method.
        /// \param[in] version One of OPENSSL_TLS_* strings.
        /// \return SSL_METHOD that supports the given version.
        _LIB_THEKOGANS_CRYPTO_DECL const SSL_METHOD * _LIB_THEKOGANS_CRYPTO_API
            GetTLSMethod (const std::string &version = OPENSSL_TLS_1_2);
        /// \brief
        /// DTLS version 1.0
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_DTLS_1_0;
        /// \brief
        /// DTLS version 1.2
        _LIB_THEKOGANS_CRYPTO_DECL extern const char * const OPENSSL_DTLS_1_2;
        /// \brief
        /// Given a string representing a version, return the
        /// corresponding DTLS method.
        /// \param[in] version One of OPENSSL_DTLS_* strings.
        /// \return SSL_METHOD that supports the given version.
        _LIB_THEKOGANS_CRYPTO_DECL const SSL_METHOD * _LIB_THEKOGANS_CRYPTO_API
            GetDTLSMethod (const std::string &version = OPENSSL_DTLS_1_2);
        /// \brief
        /// Use this callback with SSL_set_verify if you want
        /// the failed handshake error report dumped to a log.
        /// \param[in] ok 1 = handshake succeeded, 0 = handshake failed.
        /// \param[in] store Certificate store to query about
        /// the failed handshake.
        /// \return ok
        _LIB_THEKOGANS_CRYPTO_DECL int
            VerifyCallback (
                int ok,
                X509_STORE_CTX *store);
        /// \brief
        /// Perform a simple post connection check. Make sure
        /// the handshake succeeded and the host name in the
        /// server certificate matches the given server name.
        /// \param[in] ssl An established connection to check.
        /// \param[in] serverName Server name to check.
        /// \return X509_V_OK = all is well,
        /// X509_V_ERR_APPLICATION_VERIFICATION = post connection check failed.
        _LIB_THEKOGANS_CRYPTO_DECL int _LIB_THEKOGANS_CRYPTO_API
            PostConnectionCheck (
                SSL *ssl,
                const std::string &serverName);
        /// \brief
        /// Load a PEM encoded CA certificate list.
        /// \param[in] ctx SSL_CTX to load the certificate in to.
        /// \param[in] caCertificates PEM encoded CA certificates.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadCACertificates (
                SSL_CTX *ctx,
                const std::list<std::string> &caCertificates,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded certificate chain from a list of strings.
        /// \param[in] ctx SSL_CTX to load the certificates in to.
        /// \param[in] certificateChain List of strings representing a
        /// certificate chain.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadCertificateChain (
                SSL_CTX *ctx,
                const std::list<std::string> &certificateChain,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded private key from a string.
        /// \param[in] ctx SSL_CTX to load the private key in to.
        /// \param[in] privateKey String representing a private key.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadPrivateKey (
                SSL_CTX *ctx,
                const std::string &privateKey,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a ':' seperated cipher list key from a string.
        /// \param[in] ctx SSL_CTX to load the cipher list in to.
        /// \param[in] cipherList String representing a ':' seperated
        /// cipher list.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadCipherList (
                SSL_CTX *ctx,
                const std::string &cipherList);
        /// \brief
        /// Load a PEM encoded DH parameters from a string.
        /// \param[in] ctx SSL_CTX to load the DH parameters in to.
        /// \param[in] dhParams String representing DH parameters.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadDHParams (
                SSL_CTX *ctx,
                const std::string &dhParams,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);
        /// \brief
        /// Load a PEM encoded ECDH parameters from a string.
        /// \param[in] ctx SSL_CTX to load the DH parameters in to.
        /// \param[in] ecdhParamsType String representing ECDH parameters
        /// type (auto | curve | pem).
        /// \param[in] ecdhParams String representing ECDH parameters.
        /// \param[in] passwordCallback Provide a password if PEM is encrypted.
        /// \param[in] userData User data for passwordCallback.
        _LIB_THEKOGANS_CRYPTO_DECL void _LIB_THEKOGANS_CRYPTO_API
            LoadECDHParams (
                SSL_CTX *ctx,
                const std::string &ecdhParamsType,
                const std::string &ecdhParams,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLUtils_h)
