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

#include "thekogans/crypto/OpenSSLVerifier.h"
#include "thekogans/crypto/Ed25519Verifier.h"
#include "thekogans/crypto/Verifier.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_BASE (thekogans::crypto::Verifier)

        Verifier::SharedPtr Verifier::CreateVerifier (
                AsymmetricKey::SharedPtr publicKey,
                MessageDigest::SharedPtr messageDigest) {
            const TypeMap &signers = GetTypes ();
            for (TypeMap::const_iterator
                     it = signers.begin (),
                     end = signers.end (); it != end; ++it) {
                SharedPtr verifier = it->second (nullptr);
                if (verifier->HasKeyType (publicKey->GetKeyType ())) {
                    verifier->Init (publicKey, messageDigest);
                    return verifier;
                }
            }
            return nullptr;
        }

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Verifier::StaticInit () {
            OpenSSLVerifier::StaticInit ();
            Ed25519Verifier::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

    } // namespace crypto
} // namespace thekogans
