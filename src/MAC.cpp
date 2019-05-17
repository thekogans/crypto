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

#include <openssl/evp.h>
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/MAC.h"

namespace thekogans {
    namespace crypto {

        std::size_t MAC::SignBuffer (
                const void *buffer,
                std::size_t bufferLength,
                util::ui8 *signature) {
            if (buffer != 0 && bufferLength > 0 && signature != 0) {
                Init ();
                Update (buffer, bufferLength);
                return Final (signature);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer MAC::SignBuffer (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                util::Buffer signature (util::HostEndian, GetMACLength ());
                if (signature.AdvanceWriteOffset (
                        SignBuffer (buffer, bufferLength, signature.GetWritePtr ())) == GetMACLength ()) {
                    return signature;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Incorrect signature length: " THEKOGANS_UTIL_SIZE_T_FORMAT
                        " (expecting " THEKOGANS_UTIL_SIZE_T_FORMAT ").",
                        signature.GetDataAvailableForReading (),
                        GetMACLength ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool MAC::VerifyBufferSignature (
                const void *buffer,
                std::size_t bufferLength,
                const void *signature,
                std::size_t signatureLength) {
            if (buffer != 0 && bufferLength > 0 &&
                    signature != 0 && signatureLength > 0) {
                util::ui8 computedSignature[EVP_MAX_MD_SIZE];
                std::size_t computedSignatureLength =
                    SignBuffer (buffer, bufferLength, computedSignature);
                return signatureLength == computedSignatureLength &&
                    TimeInsensitiveCompare (
                        signature,
                        computedSignature,
                        signatureLength);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
