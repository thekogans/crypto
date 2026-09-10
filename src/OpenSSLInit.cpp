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
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include "thekogans/util/Config.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/crypto/OpenSSLAllocator.h"
    #include "thekogans/crypto/Serializable.h"
    #include "thekogans/crypto/Signer.h"
    #include "thekogans/crypto/Verifier.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/SystemCACertificates.h"
#include "thekogans/crypto/OpenSSLInit.h"

namespace thekogans {
    namespace crypto {

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void StaticInit () {
            util::StaticInit ();
            OpenSSLAllocator::StaticInit ();
            Serializable::StaticInit ();
            Signer::StaticInit ();
            Verifier::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        ENGINE *OpenSSLInit::engine = 0;
        int OpenSSLInit::SSLSecureSocketIndex = -1;
        int OpenSSLInit::SSL_SESSIONSessionInfoIndex = -1;

        namespace {
            void DeleteSessionInfo (
                    void *parent,
                    void *ptr,
                    CRYPTO_EX_DATA *ad,
                    int idx,
                    long argl,
                    void *argp) {
                volatile SessionInfo::SharedPtr sessionInfo ((SessionInfo *)ptr);
            }
        }

        // This is enough entropy to cover 512 bit keys.
        OpenSSLInit::OpenSSLInit (
                util::ui32 entropyNeeded,
                util::ui64 workingSetSize,
                ENGINE *engine_,
                bool loadSystemCACertificates,
                bool loadSystemRootCACertificatesOnly) {
        #if defined (THEKOGANS_CRYPTO_TYPE_Static)
            StaticInit ();
        #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
            util::SecureAllocator::ReservePages (workingSetSize, workingSetSize);
            SSL_library_init ();
            SSL_load_error_strings ();
            OpenSSL_add_all_algorithms ();
            if (entropyNeeded >= MIN_ENTROPY_NEEDED) {
                util::SecureHostBuffer entropy (entropyNeeded);
                if (entropy.AdvanceWriteOffset (
                        util::RandomSource::Instance ()->GetSeedOrBytes (
                            entropy.GetWritePtr (),
                            entropy.GetDataAvailableForWriting ())) == entropyNeeded) {
                    RAND_seed (
                        entropy.GetReadPtr (),
                        (util::i32)entropy.GetDataAvailableForReading ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get " THEKOGANS_UTIL_SIZE_T_FORMAT " random bytes for seed.",
                        entropyNeeded);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Not enough entropy: "
                    THEKOGANS_UTIL_SIZE_T_FORMAT " < " THEKOGANS_UTIL_SIZE_T_FORMAT,
                    entropyNeeded,
                    MIN_ENTROPY_NEEDED);
            }
            engine = engine_;
            if (SSLSecureSocketIndex == -1) {
                SSLSecureSocketIndex = SSL_get_ex_new_index (0, 0, 0, 0, 0);
                if (SSLSecureSocketIndex == -1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            if (SSL_SESSIONSessionInfoIndex == -1) {
                SSL_SESSIONSessionInfoIndex =
                    SSL_SESSION_get_ex_new_index (0, 0, 0, 0, DeleteSessionInfo);
                if (SSL_SESSIONSessionInfoIndex == -1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            if (loadSystemCACertificates) {
                SystemCACertificates::Instance ()->Load (loadSystemRootCACertificatesOnly);
            }
            // FIXME: load a CRL.
        }

        OpenSSLInit::~OpenSSLInit () {
            ERR_free_strings ();
            EVP_cleanup ();
            // WARNING: Do not uncomment!!!
            //OBJ_cleanup ();
        }

    } // namespace crypto
} // namespace thekogans
