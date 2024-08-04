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
#include "thekogans/util/FixedArray.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/Authenticator.h"

namespace thekogans {
    namespace crypto {

        Authenticator::Authenticator (
                AsymmetricKey::SharedPtr key,
                MessageDigest::SharedPtr messageDigest) {
            if (key.Get () != 0 && messageDigest.Get () != 0) {
                if (key->IsPrivate ()) {
                    signer = Signer::Get (key, messageDigest);
                    if (signer.Get () == 0) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get a Signer for key: %s and digest: %s.",
                            key->GetKeyType (),
                            messageDigest->GetName ().c_str ());
                    }
                }
                else {
                    verifier = Verifier::Get (key, messageDigest);
                    if (verifier.Get () == 0) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get a Verifier for key: %s and digest: %s.",
                            key->GetKeyType (),
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
            if (buffer != 0 && bufferLength > 0) {
                if (signer.Get () != 0) {
                    signer->Init ();
                    signer->Update (buffer, bufferLength);
                    return signer->Final ();
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Authenticator is setup for verify operation.");
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
            if (buffer != 0 && bufferLength > 0 &&
                    signature != 0 && signatureLength > 0) {
                if (verifier.Get () != 0) {
                    verifier->Init ();
                    verifier->Update (buffer, bufferLength);
                    return verifier->Final (signature, signatureLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Authenticator is setup for sign operation.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::SharedPtr Authenticator::SignFile (const std::string &path) {
            if (signer.Get () != 0) {
                signer->Init ();
                util::ReadOnlyFile file (util::HostEndian, path);
                util::FixedArray<util::ui8, 4096> buffer;
                for (std::size_t count = file.Read (buffer, 4096);
                        count != 0;
                        count = file.Read (buffer, 4096)) {
                    signer->Update (buffer, count);
                }
                return signer->Final ();
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "%s", "Authenticator is setup for verify operation.");
            }
        }

        bool Authenticator::VerifyFileSignature (
                const std::string &path,
                const void *signature,
                std::size_t signatureLength) {
            if (signature != 0 && signatureLength > 0) {
                if (verifier.Get () != 0) {
                    verifier->Init ();
                    util::ReadOnlyFile file (util::HostEndian, path);
                    util::FixedArray<util::ui8, 4096> buffer;
                    for (std::size_t count = file.Read (buffer, 4096);
                            count != 0;
                            count = file.Read (buffer, 4096)) {
                        verifier->Update (buffer, count);
                    }
                    return verifier->Final (signature, signatureLength);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Authenticator is setup for sign operation.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
