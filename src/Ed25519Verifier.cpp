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

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE (
            thekogans::crypto::Ed25519Verifier,
            Verifier::TYPE)

        Ed25519Verifier::Ed25519Verifier (
                AsymmetricKey::SharedPtr publicKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (publicKey_ != nullptr && messageDigest_ != nullptr) {
                Init (publicKey_, messageDigest_);
            }
        }

        bool Ed25519Verifier::HasKeyType (const std::string &keyType) {
            return keyType == Ed25519AsymmetricKey::KEY_TYPE;
        }

        void Ed25519Verifier::Init (
                AsymmetricKey::SharedPtr publicKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (publicKey_ != nullptr && messageDigest_ != nullptr) {
                Ed25519AsymmetricKey::SharedPtr key = publicKey_;
                if (key != nullptr && !key->IsPrivate ()) {
                    publicKey = publicKey_;
                    messageDigest = messageDigest_;
                    messageDigest->Init ();
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            else if (publicKey != nullptr && messageDigest != nullptr) {
                messageDigest->Init ();
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Ed25519Verifier is not initialized.");
            }
        }

        void Ed25519Verifier::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (publicKey != nullptr && messageDigest != nullptr) {
                    messageDigest->Update (buffer, bufferLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Ed25519Verifier is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Ed25519Verifier::Final (
                const void *signature,
                std::size_t signatureLength) {
            if (signature != nullptr && signatureLength == Ed25519::SIGNATURE_LENGTH) {
                if (publicKey != nullptr && messageDigest != nullptr) {
                    util::Buffer::SharedPtr digest = messageDigest->Final ();
                    Ed25519AsymmetricKey::SharedPtr key = publicKey;
                    return Ed25519::VerifyBufferSignature (
                        digest->GetReadPtr (),
                        digest->GetDataAvailableForReading (),
                        key->key.publicKey.value,
                        (const util::ui8 *)signature);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Ed25519Verifier is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
