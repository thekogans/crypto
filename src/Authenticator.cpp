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
#include "thekogans/util/FixedArray.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/Authenticator.h"

namespace thekogans {
    namespace crypto {

        Authenticator::Authenticator (
                Op op_,
                AsymmetricKey::Ptr key_,
                const EVP_MD *md_) :
                op (op_),
                key (key_),
                md (md_) {
            if (key.Get () != 0 && md != 0) {
                if ((op == Sign ?
                        EVP_DigestSignInit (&ctx, 0, md, OpenSSLInit::engine, key->Get ()) :
                        EVP_DigestVerifyInit (&ctx, 0, md, OpenSSLInit::engine, key->Get ())) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr Authenticator::SignBuffer (
                const void *buffer,
                std::size_t bufferLength) {
            if (buffer != 0 && bufferLength > 0) {
                if (EVP_DigestSignInit (&ctx, 0, md, 0, 0) == 1 &&
                        EVP_DigestSignUpdate (&ctx, buffer, bufferLength) == 1) {
                    size_t signatureLength = 0;
                    if (EVP_DigestSignFinal (&ctx, 0, &signatureLength) == 1 &&
                            signatureLength > 0) {
                        util::Buffer::UniquePtr signature (
                            new util::Buffer (util::HostEndian, (util::ui32)signatureLength));
                        if (EVP_DigestSignFinal (&ctx,
                                signature->GetWritePtr (), &signatureLength) == 1) {
                            signature->AdvanceWriteOffset ((util::ui32)signatureLength);
                            return signature;
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
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
                if (EVP_DigestVerifyInit (&ctx, 0, md, 0, 0) == 1 &&
                        EVP_DigestVerifyUpdate (&ctx, buffer, bufferLength) == 1) {
                    return EVP_DigestVerifyFinal (&ctx,
                        (const util::ui8 *)signature, signatureLength) == 1;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr Authenticator::SignFile (const std::string &path) {
            if (EVP_DigestSignInit (&ctx, 0, md, 0, 0) == 1) {
                util::ReadOnlyFile file (util::HostEndian, path);
                util::FixedArray<util::ui8, 4096> buffer;
                for (util::ui32 count = file.Read (buffer.array, 4096);
                        count != 0;
                        count = file.Read (buffer.array, 4096)) {
                    if (EVP_DigestSignUpdate (&ctx, buffer.array, count) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                size_t signatureLength = 0;
                if (EVP_DigestSignFinal (&ctx, 0, &signatureLength) == 1 && signatureLength > 0) {
                    util::Buffer::UniquePtr signature (
                        new util::Buffer (util::HostEndian, (util::ui32)signatureLength));
                    if (EVP_DigestSignFinal (&ctx,
                            signature->GetWritePtr (), &signatureLength) == 1) {
                        signature->AdvanceWriteOffset ((util::ui32)signatureLength);
                        return signature;
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        bool Authenticator::VerifyFileSignature (
                const std::string &path,
                const void *signature,
                std::size_t signatureLength) {
            if (signature != 0 && signatureLength > 0) {
                if (EVP_DigestVerifyInit (&ctx, 0, md, 0, 0) == 1) {
                    util::ReadOnlyFile file (util::HostEndian, path);
                    util::FixedArray<util::ui8, 4096> buffer;
                    for (util::ui32 count = file.Read (buffer.array, 4096);
                            count != 0;
                            count = file.Read (buffer.array, 4096)) {
                        if (EVP_DigestVerifyUpdate (&ctx, buffer.array, count) != 1) {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    return EVP_DigestVerifyFinal (&ctx,
                        (const util::ui8 *)signature, signatureLength) == 1;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
