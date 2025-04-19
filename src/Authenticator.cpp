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
#include "thekogans/util/Exception.h"
#include "thekogans/util/Array.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/Authenticator.h"

namespace thekogans {
    namespace crypto {

        Authenticator::Authenticator (
                AsymmetricKey::SharedPtr key,
                MessageDigest::SharedPtr messageDigest) {
            if (key != nullptr && messageDigest != nullptr) {
                if (key->IsPrivate ()) {
                    signer = Signer::CreateSigner (key, messageDigest);
                    if (signer == nullptr) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get a Signer for key: %s and digest: %s.",
                            key->GetKeyType ().c_str (),
                            messageDigest->GetName ().c_str ());
                    }
                }
                else {
                    verifier = Verifier::CreateVerifier (key, messageDigest);
                    if (verifier == nullptr) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get a Verifier for key: %s and digest: %s.",
                            key->GetKeyType ().c_str (),
                            messageDigest->GetName ().c_str ());
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::SharedPtr Authenticator::SignBuffer (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != nullptr && bufferLength > 0) {
                if (signer != nullptr) {
                    signer->Init ();
                    signer->Update (buffer, bufferLength);
                    return signer->Final ();
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Authenticator is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Authenticator::VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const void *signature,
                std::size_t signatureLength) {
            if (buffer != nullptr && bufferLength > 0 &&
                    signature != nullptr && signatureLength > 0) {
                if (verifier != nullptr) {
                    verifier->Init ();
                    verifier->Update (buffer, bufferLength);
                    return verifier->Final (signature, signatureLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Authenticator is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::SharedPtr Authenticator::SignFile (const std::string &path) {
            if (signer != nullptr) {
                signer->Init ();
                util::ReadOnlyFile file (util::HostEndian, path);
                static const std::size_t BUFFER_CAPACITY = 4096;
                util::Array<util::ui8> buffer (BUFFER_CAPACITY);
                std::size_t size;
                while ((size = file.Read (buffer, BUFFER_CAPACITY)) != 0) {
                    signer->Update (buffer, size);
                }
                return signer->Final ();
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Authenticator is not initialized.");
            }
        }

        bool Authenticator::VerifyFileSignature (
                const std::string &path,
                const void *signature,
                std::size_t signatureLength) {
            if (signature != nullptr && signatureLength > 0) {
                if (verifier != nullptr) {
                    verifier->Init ();
                    util::ReadOnlyFile file (util::HostEndian, path);
                    static const std::size_t BUFFER_CAPACITY = 4096;
                    util::Array<util::ui8> buffer (BUFFER_CAPACITY);
                    std::size_t size;
                    while ((size = file.Read (buffer, BUFFER_CAPACITY)) != 0) {
                        verifier->Update (buffer, size);
                    }
                    return verifier->Final (signature, signatureLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Authenticator is not initialized.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
