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

#include "thekogans/crypto/Curve25519.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/Ed25519Verifier.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (Ed25519Verifier, Ed25519AsymmetricKey::KEY_TYPE)

        Ed25519Verifier::Ed25519Verifier (
                AsymmetricKey::SharedPtr publicKey,
                MessageDigest::SharedPtr messageDigest) :
                Verifier (publicKey, messageDigest) {
            if (publicKey.Get () == 0 || publicKey->IsPrivate () ||
                    publicKey->GetKeyType () != Ed25519AsymmetricKey::KEY_TYPE) {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Ed25519Verifier::Init () {
            messageDigest->Init ();
        }

        void Ed25519Verifier::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                messageDigest->Update (buffer, bufferLength);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Ed25519Verifier::Final (
                const void *signature,
                std::size_t signatureLength) {
            if (signature != 0 && signatureLength == Ed25519::SIGNATURE_LENGTH) {
                std::vector<util::ui8> digest (messageDigest->GetDigestLength ());
                messageDigest->Final (digest.data ());
                return Ed25519::VerifyBufferSignature (
                    digest.data (),
                    digest.size (),
                    ((Ed25519AsymmetricKey *)publicKey.Get ())->key.publicKey.value,
                    (const util::ui8 *)signature);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
