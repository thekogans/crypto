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

#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/util/SpinLock.h"
    #include "thekogans/util/LockGuard.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/OpenSSLVerifier.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/Ed25519Verifier.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/Verifier.h"

namespace thekogans {
    namespace crypto {

        Verifier::Map &Verifier::GetMap () {
            static Verifier::Map map;
            return map;
        }

        Verifier::MapInitializer::MapInitializer (
                const std::string &keyType,
                Factory factory) {
            std::pair<Map::iterator, bool> result =
                GetMap ().insert (Map::value_type (keyType, factory));
            assert (result.second);
            if (!result.second) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s is already registered.", keyType.c_str ());
            }
        }

        Verifier::Verifier (
                AsymmetricKey::Ptr publicKey_,
                MessageDigest::Ptr messageDigest_) :
                publicKey (publicKey_),
                messageDigest (messageDigest_) {
            if (publicKey.Get () == 0 || messageDigest.Get () == 0) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Verifier::Ptr Verifier::Get (
                AsymmetricKey::Ptr publicKey,
                MessageDigest::Ptr messageDigest) {
            Map::iterator it = GetMap ().find (publicKey->GetKeyType ());
            return it != GetMap ().end () ? it->second (publicKey, messageDigest) : Verifier::Ptr ();
        }

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Verifier::StaticInit () {
            static volatile bool registered = false;
            static util::SpinLock spinLock;
            if (!registered) {
                util::LockGuard<util::SpinLock> guard (spinLock);
                if (!registered) {
                    OpenSSLVerifier::StaticInit (OPENSSL_PKEY_RSA);
                    OpenSSLVerifier::StaticInit (OPENSSL_PKEY_DSA);
                    OpenSSLVerifier::StaticInit (OPENSSL_PKEY_EC);
                    Ed25519Verifier::StaticInit (Ed25519AsymmetricKey::KEY_TYPE);
                    registered = true;
                }
            }
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

    } // namespace crypto
} // namespace thekogans
