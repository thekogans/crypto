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

#include "thekogans/util/Types.h"
#include "thekogans/crypto/Curve25519.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/Ed25519Signer.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE (Ed25519Signer)

        Ed25519Signer::Ed25519Signer (
                AsymmetricKey::SharedPtr privateKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (privateKey_ != nullptr && messageDigest_ != nullptr) {
                Init (privateKey_, messageDigest_);
            }
        }


        bool Ed25519Signer::HasKeyType (const std::string &keyType) {
            return keyType == Ed25519AsymmetricKey::KEY_TYPE;
        }

        void Ed25519Signer::Init (
                AsymmetricKey::SharedPtr privateKey_,
                MessageDigest::SharedPtr messageDigest_) {
            if (privateKey_ != nullptr && messageDigest_ != nullptr) {
                Ed25519AsymmetricKey::SharedPtr key = privateKey_;
                if (key != nullptr && key->IsPrivate ()) {
                    privateKey = privateKey_;
                    messageDigest = messageDigest_;
                    messageDigest->Init ();
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            else if (privateKey != nullptr && messageDigest != nullptr) {
                messageDigest->Init ();
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "Ed25519Signer is not initialized.");
            }
        }

        void Ed25519Signer::Update (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (privateKey != nullptr && messageDigest != nullptr) {
                    messageDigest->Update (buffer, bufferLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Ed25519Signer is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Ed25519Signer::Final (util::ui8 *signature) {
            if (signature != nullptr) {
                if (privateKey != nullptr && messageDigest != nullptr) {
                    util::Buffer::SharedPtr digest = messageDigest->Final ();
                    Ed25519AsymmetricKey::SharedPtr key = privateKey;
                    return Ed25519::SignBuffer (
                        digest->GetReadPtr (),
                        digest->GetDataAvailableForReading (),
                        key->key.privateKey,
                        signature);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Ed25519Signer is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
