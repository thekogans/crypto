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

#include "thekogans/util/Flags.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/HMAC.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/Cipher.h"

namespace thekogans {
    namespace crypto {

        void Cipher::Stats::Update (std::size_t byteCount) {
            ++useCount;
            if (minByteCount > byteCount) {
                minByteCount = byteCount;
            }
            if (maxByteCount < byteCount) {
                maxByteCount = byteCount;
            }
            totalByteCount += byteCount;
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const Cipher::Stats::ATTR_USE_COUNT = "UseCount";
        const char * const Cipher::Stats::ATTR_MIN_BYTE_COUNT = "MinByteCount";
        const char * const Cipher::Stats::ATTR_MAX_BYTE_COUNT = "MaxByteCount";
        const char * const Cipher::Stats::ATTR_TOTAL_BYTE_COUNT = "TotalByteCount";

        std::string Cipher::Stats::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            util::Attributes attributes;
            attributes.push_back (
                util::Attribute (
                    ATTR_USE_COUNT,
                    util::size_tTostring (useCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_MIN_BYTE_COUNT,
                    util::size_tTostring (minByteCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_MAX_BYTE_COUNT,
                    util::size_tTostring (maxByteCount)));
            attributes.push_back (
                util::Attribute (
                    ATTR_TOTAL_BYTE_COUNT,
                    util::size_tTostring (totalByteCount)));
            return util::OpenTag (indentationLevel, tagName, attributes, true, true);
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

        Cipher::Encryptor::Encryptor (
                const SymmetricKey &key,
                const EVP_CIPHER *cipher) {
            if (EVP_EncryptInit_ex (
                    &context,
                    cipher,
                    OpenSSLInit::engine,
                    key.GetReadPtr (),
                    0) != 1 ||
                    (Cipher::GetMode (cipher) == EVP_CIPH_GCM_MODE &&
                        EVP_CIPHER_CTX_ctrl (
                            &context,
                            EVP_CTRL_GCM_SET_IVLEN,
                            (util::i32)GetIVLength (),
                            0) != 1)) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        std::size_t Cipher::Encryptor::GetIV (util::ui8 *ciphertext) const {
            std::size_t ivLength = GetIVLength ();
            // An explicit iv for each frame will thwart BEAST.
            // http://www.slideshare.net/danrlde/20120418-luedtke-ssltlscbcbeast
            util::GlobalRandomSource::Instance ().GetBytes (ciphertext, ivLength);
            return ivLength;
        }

        std::size_t Cipher::Encryptor::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ivAndCiphertext) {
            std::size_t ivLength = GetIVLength ();
            util::i32 updateLength = 0;
            util::i32 finalLength = 0;
            if (EVP_EncryptInit_ex (&context, 0, 0, 0, ivAndCiphertext) == 1 &&
                    (associatedData == 0 || EVP_EncryptUpdate (
                        &context,
                        0,
                        &updateLength,
                        (const util::ui8 *)associatedData,
                        (util::i32)associatedDataLength) == 1) &&
                    EVP_EncryptUpdate (
                        &context,
                        ivAndCiphertext + ivLength,
                        &updateLength,
                        (const util::ui8 *)plaintext,
                        (util::i32)plaintextLength) == 1 &&
                    EVP_EncryptFinal_ex (
                        &context,
                        ivAndCiphertext + ivLength + updateLength,
                        &finalLength) == 1) {
                stats.Update (plaintextLength);
                return (std::size_t)(updateLength + finalLength);
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        std::size_t Cipher::Encryptor::GetTag (void *tag) {
            if (EVP_CIPHER_CTX_ctrl (
                    &context,
                    EVP_CTRL_GCM_GET_TAG,
                    EVP_GCM_TLS_TAG_LEN,
                    tag) == 1) {
                return EVP_GCM_TLS_TAG_LEN;
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        Cipher::Decryptor::Decryptor (
                const SymmetricKey &key,
                const EVP_CIPHER *cipher) {
            if (EVP_DecryptInit_ex (
                    &context,
                    cipher,
                    OpenSSLInit::engine,
                    key.GetReadPtr (),
                    0) != 1 ||
                    (Cipher::GetMode (cipher) == EVP_CIPH_GCM_MODE &&
                        EVP_CIPHER_CTX_ctrl (
                            &context,
                            EVP_CTRL_GCM_SET_IVLEN,
                            (util::i32)GetIVLength (),
                            0) != 1)) {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        std::size_t Cipher::Decryptor::Decrypt (
                const void *ivAndCiphertext,
                std::size_t ivAndCiphertextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *plaintext) {
            std::size_t ivLength = GetIVLength ();
            util::i32 updateLength = 0;
            util::i32 finalLength = 0;
            if (EVP_DecryptInit_ex (
                    &context,
                    0,
                    0,
                    0,
                    (const util::ui8 *)ivAndCiphertext) == 1 &&
                    (associatedData == 0 || EVP_DecryptUpdate (
                        &context,
                        0,
                        &updateLength,
                        (const util::ui8 *)associatedData,
                        (util::i32)associatedDataLength) == 1) &&
                    EVP_DecryptUpdate (
                        &context,
                        plaintext,
                        &updateLength,
                        (const util::ui8 *)ivAndCiphertext + ivLength,
                        (util::i32)(ivAndCiphertextLength - ivLength)) == 1 &&
                    EVP_DecryptFinal_ex (
                        &context,
                        plaintext + updateLength,
                        &finalLength) == 1) {
                stats.Update (ivAndCiphertextLength);
                return (std::size_t)(updateLength + finalLength);
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        bool Cipher::Decryptor::SetTag (
                const void *tag,
                std::size_t tagLength) {
            if (EVP_CIPHER_CTX_ctrl (
                    &context,
                    EVP_CTRL_GCM_SET_TAG,
                    (util::i32)tagLength,
                    (void *)tag) == 1) {
                return true;
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        Cipher::Cipher (
                SymmetricKey::Ptr key_,
                const EVP_CIPHER *cipher_,
                const EVP_MD *md_) :
                key (key_),
                cipher (cipher_),
                md (md_),
                encryptor (*key, cipher),
                decryptor (*key, cipher) {
            if (key.Get () != 0 && cipher != 0) {
                if (GetMode (cipher) != EVP_CIPH_GCM_MODE) {
                    if (md != 0) {
                        mac.reset (
                            new MAC (
                                HMAC::CreateKey (
                                    key->GetReadPtr (),
                                    key->GetDataAvailableForReading (),
                                    md)));
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

        std::size_t Cipher::GetKeyLength (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return EVP_CIPHER_key_length (cipher);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::i32 Cipher::GetMode (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return EVP_CIPHER_mode (cipher);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Cipher::IsAEAD (const EVP_CIPHER *cipher) {
            if (cipher != 0) {
                return util::Flags<unsigned long> (EVP_CIPHER_flags (cipher)).Test (
                    EVP_CIPH_FLAG_AEAD_CIPHER);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Cipher::GetMaxBufferLength (std::size_t plaintextLength) {
            return
                FrameHeader::SIZE +
                CiphertextHeader::SIZE +
                EVP_MAX_IV_LENGTH + // iv
                plaintextLength + EVP_MAX_BLOCK_LENGTH + // ciphertext
                EVP_MAX_MD_SIZE; // mac
        }

        std::size_t Cipher::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    ciphertext != 0) {
                util::ui8 *ivCiphertextAndMAC = ciphertext + CiphertextHeader::SIZE;
                CiphertextHeader ciphertextHeader;
                ciphertextHeader.ivLength = (util::ui16)encryptor.GetIV (ivCiphertextAndMAC);
                ciphertextHeader.ciphertextLength = (util::ui32)encryptor.Encrypt (
                    plaintext,
                    plaintextLength,
                    associatedData,
                    associatedDataLength,
                    ivCiphertextAndMAC);
                if (mac.get () != 0) {
                    ciphertextHeader.macLength = (util::ui16)mac->SignBuffer (
                        ivCiphertextAndMAC,
                        ciphertextHeader.ivLength + ciphertextHeader.ciphertextLength,
                        ivCiphertextAndMAC + ciphertextHeader.ivLength + ciphertextHeader.ciphertextLength);
                }
                else {
                    ciphertextHeader.macLength = (util::ui16)encryptor.GetTag (
                        ivCiphertextAndMAC + ciphertextHeader.ivLength + ciphertextHeader.ciphertextLength);
                }
                util::TenantWriteBuffer buffer (
                    util::NetworkEndian,
                    ciphertext,
                    CiphertextHeader::SIZE);
                buffer << ciphertextHeader;
                return CiphertextHeader::SIZE + ciphertextHeader.GetTotalLength ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr Cipher::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer::UniquePtr ciphertext (
                    new util::Buffer (
                        util::NetworkEndian,
                        (util::ui32)GetMaxBufferLength (plaintextLength)));
                ciphertext->AdvanceWriteOffset (
                    (util::ui32)Encrypt (
                        plaintext,
                        plaintextLength,
                        associatedData,
                        associatedDataLength,
                        ciphertext->GetWritePtr ()));
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
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    ciphertext != 0) {
                std::size_t ciphertextLength = Encrypt (
                    plaintext,
                    plaintextLength,
                    associatedData,
                    associatedDataLength,
                    ciphertext + FrameHeader::SIZE);
                util::TenantWriteBuffer buffer (
                    util::NetworkEndian,
                    ciphertext,
                    FrameHeader::SIZE);
                buffer << FrameHeader (key->GetId (), (util::ui32)ciphertextLength);
                return FrameHeader::SIZE + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr Cipher::EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (plaintext != 0 && plaintextLength > 0 && plaintextLength < MAX_PLAINTEXT_LENGTH &&
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                util::Buffer::UniquePtr ciphertext (
                    new util::Buffer (
                        util::NetworkEndian,
                        (util::ui32)(FrameHeader::SIZE + GetMaxBufferLength (plaintextLength))));
                ciphertext->AdvanceWriteOffset (
                    (util::ui32)EncryptAndFrame (
                        plaintext,
                        plaintextLength,
                        associatedData,
                        associatedDataLength,
                        ciphertext->GetWritePtr ()));
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
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0)) &&
                    plaintext != 0) {
                CiphertextHeader ciphertextHeader;
                util::TenantReadBuffer buffer (
                    util::NetworkEndian,
                    (const util::ui8 *)ciphertext,
                    (util::ui32)ciphertextLength);
                buffer >> ciphertextHeader;
                util::ui32 ivAndCiphertextLength =
                    ciphertextHeader.ivLength + ciphertextHeader.ciphertextLength;
                if (mac.get () != 0 ?
                        mac->VerifyBufferSignature (
                            buffer.GetReadPtr (),
                            ivAndCiphertextLength,
                            buffer.GetReadPtr () + ivAndCiphertextLength,
                            ciphertextHeader.macLength) :
                        decryptor.SetTag (
                            buffer.GetReadPtr () + ivAndCiphertextLength,
                            ciphertextHeader.macLength)) {
                    return decryptor.Decrypt (
                        buffer.GetReadPtr (),
                        ivAndCiphertextLength,
                        associatedData,
                        associatedDataLength,
                        plaintext);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Ciphertext failed mac verifacion.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer::UniquePtr Cipher::Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                const void *associatedData,
                std::size_t associatedDataLength,
                bool secure,
                util::Endianness endianness) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    (IsAEAD (cipher) || (associatedData == 0 && associatedDataLength == 0))) {
                CiphertextHeader ciphertextHeader;
                util::TenantReadBuffer buffer (
                    util::NetworkEndian,
                    (const util::ui8 *)ciphertext,
                    (util::ui32)ciphertextLength);
                buffer >> ciphertextHeader;
                util::ui32 ivAndCiphertextLength =
                    ciphertextHeader.ivLength + ciphertextHeader.ciphertextLength;
                if (mac.get () != 0 ?
                        mac->VerifyBufferSignature (
                            buffer.GetReadPtr (),
                            ivAndCiphertextLength,
                            buffer.GetReadPtr () + ivAndCiphertextLength,
                            ciphertextHeader.macLength) :
                        decryptor.SetTag (
                            buffer.GetReadPtr () + ivAndCiphertextLength,
                            ciphertextHeader.macLength)) {
                    util::Buffer::UniquePtr plaintext (secure ?
                        new util::SecureBuffer (endianness, ivAndCiphertextLength) :
                        new util::Buffer (endianness, ivAndCiphertextLength));
                    plaintext->AdvanceWriteOffset (
                        (util::ui32)decryptor.Decrypt (
                            buffer.GetReadPtr (),
                            ivAndCiphertextLength,
                            associatedData,
                            associatedDataLength,
                            plaintext->GetWritePtr ()));
                    return plaintext;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "%s", "Ciphertext failed mac verifacion.");
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
