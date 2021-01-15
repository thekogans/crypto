// Copyright 2016 Boris Kogan (boris@thekogans.net)
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

#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/HMAC.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/Cipher.h"

namespace thekogans {
    namespace crypto {

        Cipher::Cipher (
                SymmetricKey::SharedPtr key_,
                const EVP_CIPHER *cipher_,
                const EVP_MD *md_) :
                key (key_),
                cipher (cipher_),
                md (md_),
                encryptor (key, cipher),
                decryptor (key, cipher) {
            if (key.Get () != 0 && cipher != 0 &&
                    key->GetKeyLength () == GetCipherKeyLength (cipher)) {
                if (GetCipherMode (cipher) != EVP_CIPH_GCM_MODE) {
                    if (md != 0) {
                        mac.Reset (
                            new HMAC (
                                SymmetricKey::FromSecretAndSalt (
                                    key->Get ().GetReadPtr (),
                                    key->Get ().GetDataAvailableForReading (),
                                    0,
                                    0,
                                    GetMDLength (md),
                                    md),
                                md));
                    }
                    else {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                    }
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Cipher::GetMaxPlaintextLength (std::size_t payloadLength) {
            return payloadLength > MAX_FRAMING_OVERHEAD_LENGTH ?
                payloadLength - MAX_FRAMING_OVERHEAD_LENGTH : 0;
        }

        std::size_t Cipher::GetMaxBufferLength (std::size_t plaintextLength) {
            return plaintextLength + MAX_FRAMING_OVERHEAD_LENGTH;
        }

        std::size_t Cipher::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    ciphertext != 0) {
                util::ui8 *ivCiphertextAndMAC = ciphertext + CiphertextHeader::SIZE;
                CiphertextHeader ciphertextHeader;
                ciphertextHeader.ivLength =
                    (util::ui16)encryptor.Init (ivCiphertextAndMAC);
                if (associatedData != 0) {
                    encryptor.SetAssociatedData (
                        associatedData,
                        associatedDataLength);
                }
                std::size_t updateLength = encryptor.Update (
                    plaintext,
                    plaintextLength,
                    ivCiphertextAndMAC + ciphertextHeader.ivLength);
                std::size_t finalLength = encryptor.Final (
                    ivCiphertextAndMAC + ciphertextHeader.ivLength + updateLength);
                ciphertextHeader.ciphertextLength =
                    (util::ui32)(updateLength + finalLength);
                if (mac.Get () != 0) {
                    ciphertextHeader.macLength =
                        (util::ui16)mac->SignBuffer (
                            ivCiphertextAndMAC,
                            ciphertextHeader.ivLength +
                                ciphertextHeader.ciphertextLength,
                            ivCiphertextAndMAC +
                                ciphertextHeader.ivLength +
                                ciphertextHeader.ciphertextLength);
                }
                else {
                    ciphertextHeader.macLength =
                        (util::ui16)encryptor.GetTag (
                            ivCiphertextAndMAC +
                            ciphertextHeader.ivLength +
                            ciphertextHeader.ciphertextLength);
                }
                util::TenantWriteBuffer buffer (util::NetworkEndian, ciphertext, CiphertextHeader::SIZE);
                buffer << ciphertextHeader;
                return CiphertextHeader::SIZE + ciphertextHeader.GetTotalLength ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer Cipher::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer ciphertext (util::NetworkEndian, GetMaxBufferLength (plaintextLength));
                ciphertext.AdvanceWriteOffset (
                    Encrypt (
                        plaintext,
                        plaintextLength,
                        associatedData,
                        associatedDataLength,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Cipher::EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    ciphertext != 0) {
                std::size_t ciphertextLength = Encrypt (
                    plaintext,
                    plaintextLength,
                    associatedData,
                    associatedDataLength,
                    ciphertext + util::UI32_SIZE);
                util::TenantWriteBuffer buffer (util::NetworkEndian, ciphertext, util::UI32_SIZE);
                buffer << (util::ui32)ciphertextLength;
                return util::UI32_SIZE + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer Cipher::EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer ciphertext (util::NetworkEndian, GetMaxBufferLength (plaintextLength));
                ciphertext.AdvanceWriteOffset (
                    EncryptAndEnlengthen (
                        plaintext,
                        plaintextLength,
                        associatedData,
                        associatedDataLength,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Cipher::EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    ciphertext != 0) {
                std::size_t ciphertextLength = Encrypt (
                    plaintext,
                    plaintextLength,
                    associatedData,
                    associatedDataLength,
                    ciphertext + FrameHeader::SIZE);
                util::TenantWriteBuffer buffer (util::NetworkEndian, ciphertext, FrameHeader::SIZE);
                buffer << FrameHeader (key->GetId (), (util::ui32)ciphertextLength);
                return FrameHeader::SIZE + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer Cipher::EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer ciphertext (util::NetworkEndian, GetMaxBufferLength (plaintextLength));
                ciphertext.AdvanceWriteOffset (
                    EncryptAndFrame (
                        plaintext,
                        plaintextLength,
                        associatedData,
                        associatedDataLength,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Cipher::Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *plaintext) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    plaintext != 0) {
                util::TenantReadBuffer buffer (util::NetworkEndian, ciphertext, ciphertextLength);
                CiphertextHeader ciphertextHeader;
                buffer >> ciphertextHeader;
                // If we're in CBC mode, verify the MAC before attempting to
                // decrypt, as per the Cryptographic Doom Principle:
                // https://moxie.org/blog/the-cryptographic-doom-principle/
                if (mac.Get () != 0 &&
                        !mac->VerifyBufferSignature (
                            buffer.GetReadPtr (),
                            ciphertextHeader.ivLength +
                                ciphertextHeader.ciphertextLength,
                            buffer.GetReadPtr () +
                                ciphertextHeader.ivLength +
                                ciphertextHeader.ciphertextLength,
                            ciphertextHeader.macLength)) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Ciphertext failed mac verifacion.");
                }
                decryptor.Init (buffer.GetReadPtr ());
                buffer.AdvanceReadOffset (ciphertextHeader.ivLength);
                if (associatedData != 0 && associatedDataLength > 0) {
                    decryptor.SetAssociatedData (associatedData, associatedDataLength);
                }
                std::size_t updateLength = decryptor.Update (
                    buffer.GetReadPtr (),
                    ciphertextHeader.ciphertextLength,
                    plaintext);
                buffer.AdvanceReadOffset (ciphertextHeader.ciphertextLength);
                if (mac.Get () == 0) {
                    decryptor.SetTag (
                        buffer.GetReadPtr (),
                        ciphertextHeader.macLength);
                }
                std::size_t finalLength = decryptor.Final (plaintext + updateLength);
                return updateLength + finalLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer Cipher::Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                bool secure,
                util::Endianness endianness) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    (IsCipherAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer plaintext = secure ?
                    util::SecureBuffer (endianness, ciphertextLength) :
                    util::Buffer (endianness, ciphertextLength);
                plaintext.AdvanceWriteOffset (
                    Decrypt (
                        ciphertext,
                        ciphertextLength,
                        associatedData,
                        associatedDataLength,
                        plaintext.GetWritePtr ()));
                return plaintext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
