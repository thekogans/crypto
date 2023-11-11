// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#include "thekogans/util/Environment.h"
#if defined (TOOLCHAIN_OS_Windows)
    #if !defined (_WINDOWS_)
        #if !defined (WIN32_LEAN_AND_MEAN)
            #define WIN32_LEAN_AND_MEAN
        #endif // !defined (WIN32_LEAN_AND_MEAN)
        #if !defined (NOMINMAX)
            #define NOMINMAX
        #endif // !defined (NOMINMAX)
        #include <windows.h>
    #endif // !defined (_WINDOWS_)
    #include <winsock2.h>
    #include <wincrypt.h>
#elif defined (TOOLCHAIN_OS_OSX)
    #include <CoreFoundation/CoreFoundation.h>
    #include <Security/Security.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <memory>
#include <string>
#include <openssl/ssl.h>
#include "thekogans/util/Array.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/LoggerMgr.h"
#if defined (TOOLCHAIN_OS_Windows)
    #include "thekogans/util/os/windows/WindowsUtils.h"
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/SystemCACertificates.h"

namespace thekogans {
    namespace crypto {

        namespace {
        #if defined (TOOLCHAIN_OS_Windows)
            const DWORD ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

            std::string encodingTostring (DWORD encoding) {
                return encoding == X509_ASN_ENCODING ? DER_ENCODING :
                    encoding == PKCS_7_ASN_ENCODING ? PEM_ENCODING : std::string ();
            }

            std::string GetCertName (
                    DWORD encoding,
                    PCERT_NAME_BLOB certName) {
                DWORD size = CertNameToStrW (
                    encoding,
                    certName,
                    CERT_SIMPLE_NAME_STR,
                    0, 0);
                if (size != 0) {
                    util::Array<wchar_t> buffer (size);
                    CertNameToStrW (
                        encoding,
                        certName,
                        CERT_SIMPLE_NAME_STR,
                        buffer,
                        size);
                    return util::os::windows::UTF16ToUTF8 (buffer, size);
                }
                return std::string ();
            }
        #elif defined (TOOLCHAIN_OS_OSX)
            struct CFArrayRefDeleter {
                void operator () (CFArrayRef arrayRef) {
                    if (arrayRef != 0) {
                        CFRelease (arrayRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFArray, CFArrayRefDeleter> CFArrayRefPtr;

            struct CFDictionaryRefDeleter {
                void operator () (CFDictionaryRef dictionaryRef) {
                    if (dictionaryRef != 0) {
                        CFRelease (dictionaryRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFDictionary, CFDictionaryRefDeleter> CFDictionaryRefPtr;

            struct CFErrorRefDeleter {
                void operator () (CFErrorRef errorRef) {
                    if (errorRef != 0) {
                        CFRelease (errorRef);
                    }
                }
            };
            typedef std::unique_ptr<__CFError, CFErrorRefDeleter> CFErrorRefPtr;

            struct CFDataRefDeleter {
                void operator () (CFDataRef dataRef) {
                    if (dataRef != 0) {
                        CFRelease (dataRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFData, CFDataRefDeleter> CFDataRefPtr;

            struct CFDateRefDeleter {
                void operator () (CFDateRef dateRef) {
                    if (dateRef != 0) {
                        CFRelease (dateRef);
                    }
                }
            };
            typedef std::unique_ptr<const __CFDate, CFDateRefDeleter> CFDateRefPtr;

            bool CheckDateRange (
                    CFNumberRef notBefore,
                    CFNumberRef notAfter) {
                CFDateRefPtr now (CFDateCreate (0, CFAbsoluteTimeGetCurrent ()));
                if (now.get () != 0) {
                    CFAbsoluteTime validityNotBefore;
                    CFAbsoluteTime validityNotAfter;
                    if (CFNumberGetValue (notBefore, kCFNumberDoubleType, &validityNotBefore) &&
                            CFNumberGetValue (notAfter, kCFNumberDoubleType, &validityNotAfter)) {
                        CFDateRefPtr notBeforeDate (CFDateCreate (0, validityNotBefore));
                        CFDateRefPtr notAfterDate (CFDateCreate (0, validityNotAfter));
                        return notBeforeDate.get () != 0 && notAfterDate.get () != 0 &&
                            CFDateCompare (notBeforeDate.get (), now.get (), 0) == kCFCompareLessThan &&
                            CFDateCompare (now.get (), notAfterDate.get (), 0) == kCFCompareLessThan;
                    }
                }
                return false;
            }
        #endif // defined (TOOLCHAIN_OS_OSX)
        }

        void SystemCACertificates::Load (bool loadSystemRootCACertificatesOnly) throw () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            certificates.clear ();
        #if defined (TOOLCHAIN_OS_Windows)
            struct SystemStore {
                HCERTSTORE certStore;
                explicit SystemStore (const wchar_t *storeName) :
                        certStore (CertOpenSystemStoreW (0, storeName)) {
                    if (certStore == 0) {
                        THEKOGANS_UTIL_LOG_SUBSYSTEM_EXCEPTION_WITH_MESSAGE (
                            THEKOGANS_CRYPTO,
                            THEKOGANS_UTIL_ERROR_CODE_EXCEPTION (THEKOGANS_UTIL_OS_ERROR_CODE),
                            "\nLoading '%s'",
                            util::os::windows::UTF16ToUTF8 (std::wstring (storeName)).c_str ());
                    }
                }
                ~SystemStore () {
                    CertCloseStore (certStore, 0);
                }
            };
            SystemStore rootStore (L"ROOT");
            SystemStore caStore (L"CA");
            SystemStore myStore (L"MY");
            SystemStore *stores[] = {
                &rootStore,
                &caStore,
                &myStore
            };
            for (std::size_t i = 0, numStores = THEKOGANS_UTIL_ARRAY_SIZE (stores); i < numStores; ++i) {
                if (stores[i]->certStore != 0) {
                    PCCERT_CONTEXT certContext = 0;
                    while ((certContext = CertEnumCertificatesInStore (stores[i]->certStore, certContext)) != 0) {
                        // Skip expired certificates.
                        if (CertVerifyTimeValidity (0, certContext->pCertInfo) == 0) {
                            if (loadSystemRootCACertificatesOnly) {
                                // We only want to add Root CAs, so make
                                // sure Subject and Issuer names match.
                                std::string subject =
                                    GetCertName (
                                        certContext->dwCertEncodingType,
                                        &certContext->pCertInfo->Subject);
                                std::string issuer =
                                    GetCertName (
                                        certContext->dwCertEncodingType,
                                        &certContext->pCertInfo->Issuer);
                                if (subject.empty () || issuer.empty () || subject != issuer) {
                                    continue;
                                }
                            }
                            // Bad certificates are logged and ignored.
                            THEKOGANS_UTIL_TRY {
                                X509Ptr certificate =
                                    ParseCertificate (
                                        certContext->pbCertEncoded,
                                        certContext->cbCertEncoded,
                                        encodingTostring (certContext->dwCertEncodingType));
                                // ParseCertificate either returns a valid certificate or it will throw.
                                certificates.push_back (std::move (certificate));
                            }
                            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_CRYPTO)
                        }
                    }
                }
            }
       #elif defined (TOOLCHAIN_OS_Linux)
            // FIXME: implement
            assert (0);
       #elif defined (TOOLCHAIN_OS_OSX)
            // This code was adapted from: https://github.com/raggi/openssl-osx-ca
            // Get certificates from all domains, not just System, this lets
            // the user add CAs to their "login" keychain, and Admins to add
            // to the "System" keychain
            SecTrustSettingsDomain domains[] = {
                kSecTrustSettingsDomainSystem,
                kSecTrustSettingsDomainAdmin,
                kSecTrustSettingsDomainUser
            };
            CFStringRef x509OID[] = {
                kSecOIDX509V1ValidityNotBefore,
                kSecOIDX509V1ValidityNotAfter,
                kSecOIDX509V1SubjectName,
                kSecOIDX509V1IssuerName
            };
            CFArrayRefPtr x509Keys (
                CFArrayCreate (0,
                    (const void **)x509OID,
                    THEKOGANS_UTIL_ARRAY_SIZE (x509OID),
                    &kCFTypeArrayCallBacks));
            for (std::size_t i = 0, numDomains = THEKOGANS_UTIL_ARRAY_SIZE (domains); i < numDomains; ++i) {
                CFArrayRef certs = 0;
                /*OSStatus errorCode =*/ SecTrustSettingsCopyCertificates (domains[i], &certs);
                if (certs != 0) {
                    CFArrayRefPtr certsPtr (certs);
                    for (CFIndex j = 0, numCerts = (util::i32)CFArrayGetCount (certs); j < numCerts; ++j) {
                        SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex (certs, j);
                        if (cert != 0) {
                            CFErrorRef error = 0;
                            CFDictionaryRefPtr names (
                                SecCertificateCopyValues (cert, x509Keys.get (), &error));
                            if (names != 0) {
                                // Check if the certificate expired.
                                CFNumberRef notBefore =
                                    (CFNumberRef)CFDictionaryGetValue (
                                        (CFDictionaryRef)CFDictionaryGetValue (
                                            names.get (),
                                            kSecOIDX509V1ValidityNotBefore),
                                        kSecPropertyKeyValue);
                                CFNumberRef notAfter =
                                    (CFNumberRef)CFDictionaryGetValue (
                                        (CFDictionaryRef)CFDictionaryGetValue (
                                            names.get (),
                                            kSecOIDX509V1ValidityNotAfter),
                                        kSecPropertyKeyValue);
                                if (notBefore != 0 && notAfter != 0 && CheckDateRange (notBefore, notAfter)) {
                                    if (loadSystemRootCACertificatesOnly) {
                                        // We only want to add Root CAs, so make
                                        // sure Subject and Issuer names match.
                                        CFStringRef issuer =
                                            (CFStringRef)CFDictionaryGetValue (
                                                (CFDictionaryRef)CFDictionaryGetValue (
                                                    names.get (),
                                                    kSecOIDX509V1IssuerName),
                                                kSecPropertyKeyValue);
                                        CFStringRef subject =
                                            (CFStringRef)CFDictionaryGetValue(
                                                (CFDictionaryRef)CFDictionaryGetValue (
                                                    names.get (),
                                                    kSecOIDX509V1SubjectName),
                                                kSecPropertyKeyValue);
                                        if (issuer == 0 || subject == 0 || !CFEqual (subject, issuer)) {
                                            continue;
                                        }
                                    }
                                    CFDataRef data = 0;
                                    /*OSStatus errorCode =*/
                                        SecItemExport (cert, kSecFormatX509Cert, kSecItemPemArmour, 0, &data);
                                    if (data != 0) {
                                        CFDataRefPtr dataPtr (data);
                                        // Bad certificates are logged and ignored.
                                        THEKOGANS_UTIL_TRY {
                                            // Apple certificates are PEM encoded.
                                            X509Ptr certificate =
                                                ParseCertificate (
                                                    CFDataGetBytePtr (data),
                                                    CFDataGetLength (data),
                                                    PEM_ENCODING);
                                            // ParseCertificate either returns a valid certificate or it will throw.
                                            certificates.push_back (std::move (certificate));
                                        }
                                        THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_CRYPTO)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        #endif // defined (TOOLCHAIN_OS_Windows)
        }

        void SystemCACertificates::Use (SSL_CTX *ctx) {
            if (ctx != 0) {
                util::LockGuard<util::SpinLock> guard (spinLock);
                X509_STOREPtr newStore;
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
                for (std::list<X509Ptr>::const_iterator
                        it = certificates.begin (),
                        end = certificates.end (); it != end; ++it) {
                    if (X509_STORE_add_cert (store, (*it).get ()) != 1) {
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

        void SystemCACertificates::Flush () {
            util::LockGuard<util::SpinLock> guard (spinLock);
            certificates.clear ();
        }

    } // namespace crypto
} // namespace thekogans
