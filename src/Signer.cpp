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

#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/OpenSSLSigner.h"
#include "thekogans/crypto/Ed25519Signer.h"
#include "thekogans/crypto/Signer.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_BASE (Signer)

        Signer::SharedPtr Signer::CreateSigner (
                AsymmetricKey::SharedPtr privateKey,
                MessageDigest::SharedPtr messageDigest) {
            std::list<std::string> signers;
            GetTypes (signers);
            for (std::list<std::string>::const_iterator
                     it = signers.begin (),
                     end = signers.end (); it != end; ++it) {
                SharedPtr signer = CreateType (*it);
                if (signer->HasKeyType (privateKey->GetKeyType ())) {
                    signer->Init (privateKey, messageDigest);
                    return signer;
                }
            }
            return nullptr;
        }

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void Signer::StaticInit () {
            OpenSSLSigner::StaticInit ();
            Ed25519Signer::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        util::Buffer::SharedPtr Signer::Final () {
            util::Buffer::SharedPtr signature (
                new util::HostBuffer (privateKey->GetKeyLength ()));
            signature->AdvanceWriteOffset (Final (signature->GetWritePtr ()));
            return signature;
        }

    } // namespace crypto
} // namespace thekogans
