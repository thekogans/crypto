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

#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "thekogans/util/OwnerVector.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Thread.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/Keys.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/OpenSSLInit.h"

namespace thekogans {
    namespace crypto {

        ENGINE *OpenSSLInit::engine = 0;

    #if OPENSSL_VERSION_NUMBER < 0x10100000L
        namespace {
            util::OwnerVector<util::SpinLock> staticLocks;

            void LockingFunction (
                    util::i32 mode,
                    util::i32 lockIndex,
                    const char *file,
                    util::i32 line) {
                if (mode & CRYPTO_LOCK) {
                    staticLocks[lockIndex]->Acquire ();
                }
                else {
                    staticLocks[lockIndex]->Release ();
                }
            }

            unsigned long IdFunction () {
                return (unsigned long)(unsigned long long)util::Thread::GetCurrThreadHandle ();
            }

            struct CRYPTO_dynlock_value *DynlockCreateFunction (
                    const char *file,
                    util::i32 line) {
                return (struct CRYPTO_dynlock_value *)new util::SpinLock;
            }

            void DynlockLockFunction (
                    util::i32 mode,
                    struct CRYPTO_dynlock_value *lock,
                    const char *file,
                    util::i32 line) {
                if (mode & CRYPTO_LOCK) {
                    reinterpret_cast<util::SpinLock *> (lock)->Acquire ();
                }
                else {
                    reinterpret_cast<util::SpinLock *> (lock)->Release ();
                }
            }

            void DynlockDestroyFunction (
                    struct CRYPTO_dynlock_value *lock,
                    const char *file,
                    util::i32 line) {
                delete reinterpret_cast<util::SpinLock *> (lock);
            }

            void ExitFunc (THEKOGANS_UTIL_THREAD_HANDLE thread) {
                CRYPTO_THREADID threadId;
                CRYPTO_THREADID_set_numeric (&threadId, (unsigned long)(unsigned long long)thread);
                ERR_remove_thread_state (&threadId);
            }
        }
    #endif // OPENSSL_VERSION_NUMBER < 0x10100000L

        // This is enough entropy to cover 512 bit keys.
        OpenSSLInit::OpenSSLInit (
                bool multiThreaded,
                util::ui32 entropyNeeded,
                util::ui64 workingSetSize) {
        #if defined (TOOLCHAIN_TYPE_Static)
            Keys::StaticInit ();
        #endif // defined (TOOLCHAIN_TYPE_Static)
            util::SecureAllocator::ReservePages (workingSetSize, workingSetSize);
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
            if (multiThreaded) {
                util::i32 lockCount = CRYPTO_num_locks ();
                if (lockCount > 0) {
                    staticLocks.resize (lockCount);
                    for (util::i32 i = 0; i < lockCount; ++i) {
                        staticLocks[i] = new util::SpinLock;
                    }
                }
                // Static lock callbacks.
                CRYPTO_set_locking_callback (LockingFunction);
                CRYPTO_set_id_callback (IdFunction);
                // Dynamic locks callbacks.
                CRYPTO_set_dynlock_create_callback (DynlockCreateFunction);
                CRYPTO_set_dynlock_lock_callback (DynlockLockFunction);
                CRYPTO_set_dynlock_destroy_callback (DynlockDestroyFunction);
            }
        #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
            SSL_library_init ();
            SSL_load_error_strings ();
            OpenSSL_add_all_algorithms ();
            if (entropyNeeded >= MIN_ENTROPY_NEEDED) {
                util::SecureBuffer entropy (util::HostEndian, entropyNeeded);
                {
                    util::RandomSource randomSource;
                    randomSource.GetBytes (entropy.data, entropy.length);
                }
                RAND_seed (entropy.data, (util::i32)entropy.length);
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Not enough entropy: %u < %u",
                    entropyNeeded, MIN_ENTROPY_NEEDED);
            }
            // FIXME: load a CRL.
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
            util::Thread::AddExitFunc (ExitFunc);
        #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
        }

        OpenSSLInit::~OpenSSLInit () {
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
            CRYPTO_set_dynlock_destroy_callback (0);
            CRYPTO_set_dynlock_lock_callback (0);
            CRYPTO_set_dynlock_create_callback (0);
            CRYPTO_set_id_callback (0);
            CRYPTO_set_locking_callback (0);
            staticLocks.deleteAndClear ();
        #endif // OPENSSL_VERSION_NUMBER < 0x10100000L
            ERR_free_strings ();
            EVP_cleanup ();
        }

    } // namespace crypto
} // namespace thekogans
