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

#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/DefaultAllocator.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/DHEKeyExchange.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            DHEKeyExchange::DHEParams,
            1,
            util::SpinLock,
            16,
            util::DefaultAllocator::Global)

        void DHEKeyExchange::DHEParams::CreateSignature (
                AsymmetricKey::Ptr privateKey,
                const EVP_MD *md) {
            if (privateKey.Get () != 0 && md != 0) {
                util::Buffer paramsBuffer (
                    util::NetworkEndian,
                    util::Serializer::Size (id) +
                    util::Serializable::Size (*params) +
                    util::Serializer::Size (salt) +
                    util::Serializer::Size (keyLength) +
                    util::Serializer::Size (messageDigest) +
                    util::Serializer::Size (count) +
                    util::Serializer::Size (keyId) +
                    util::Serializer::Size (name) +
                    util::Serializer::Size (description) +
                    util::Serializable::Size (*publicKey));
                paramsBuffer <<
                    id <<
                    *params <<
                    salt <<
                    keyLength <<
                    messageDigest <<
                    count <<
                    keyId <<
                    name <<
                    description <<
                    *publicKey;
                Authenticator authenticator (Authenticator::Sign, privateKey, md);
                signature = authenticator.SignBuffer (
                    paramsBuffer.GetReadPtr (),
                    paramsBuffer.GetDataAvailableForReading ());
                signatureKeyId = privateKey->GetId ();
                signatureMessageDigest = CipherSuite::GetOpenSSLMessageDigestName (md);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool DHEKeyExchange::DHEParams::ValidateSignature (
                AsymmetricKey::Ptr publicKey,
                const EVP_MD *md) {
            if (publicKey.Get () != 0 && md != 0 &&
                    publicKey->GetId () == signatureKeyId &&
                    CipherSuite::GetOpenSSLMessageDigestName (md) == signatureMessageDigest) {
                if (!signature.IsEmpty ()) {
                    util::Buffer paramsBuffer (
                        util::NetworkEndian,
                        util::Serializer::Size (id) +
                        util::Serializable::Size (*params) +
                        util::Serializer::Size (salt) +
                        util::Serializer::Size (keyLength) +
                        util::Serializer::Size (messageDigest) +
                        util::Serializer::Size (count) +
                        util::Serializer::Size (keyId) +
                        util::Serializer::Size (name) +
                        util::Serializer::Size (description) +
                        util::Serializable::Size (*this->publicKey));
                    paramsBuffer <<
                        id <<
                        *params <<
                        salt <<
                        keyLength <<
                        messageDigest <<
                        count <<
                        keyId <<
                        name <<
                        description <<
                        *this->publicKey;
                    Authenticator authenticator (Authenticator::Verify, publicKey, md);
                    return authenticator.VerifyBufferSignature (
                        paramsBuffer.GetReadPtr (),
                        paramsBuffer.GetDataAvailableForReading (),
                        signature.GetReadPtr (),
                        signature.GetDataAvailableForReading ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Params (%s) are not signed.",
                        id.ToString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t DHEKeyExchange::DHEParams::Size () const {
            return
                Params::Size () +
                util::Serializable::Size (*params) +
                util::Serializer::Size (salt) +
                util::Serializer::Size (keyLength) +
                util::Serializer::Size (messageDigest) +
                util::Serializer::Size (count) +
                util::Serializer::Size (keyId) +
                util::Serializer::Size (name) +
                util::Serializer::Size (description) +
                util::Serializable::Size (*publicKey);
        }

        void DHEKeyExchange::DHEParams::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            serializer >>
                params >>
                salt >>
                keyLength >>
                messageDigest >>
                count >>
                keyId >>
                name >>
                description >>
                publicKey;
        }

        void DHEKeyExchange::DHEParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer <<
                *params <<
                salt <<
                keyLength <<
                messageDigest <<
                count <<
                keyId <<
                name <<
                description <<
                *publicKey;
        }

        DHEKeyExchange::DHEKeyExchange (
                const ID &id,
                crypto::Params::Ptr params_,
                const void *salt_,
                std::size_t saltLength_,
                std::size_t keyLength_,
                const EVP_MD *md_,
                std::size_t count_,
                const ID &keyId_,
                const std::string &name_,
                const std::string &description_) :
                KeyExchange (id),
                initiator (true),
                params (params_),
                salt (
                    salt_ != 0 && saltLength_ > 0 ?
                        std::vector<util::ui8> (
                            (const util::ui8 *)salt_,
                            (const util::ui8 *)salt_ + saltLength_) :
                    std::vector<util::ui8> ()),
                keyLength (keyLength_),
                messageDigest (CipherSuite::GetOpenSSLMessageDigestName (md_)),
                count (count_),
                keyId (keyId_),
                name (name_),
                description (description_) {
            util::i32 type = params->GetType ();
            if (type == EVP_PKEY_DH || type == EVP_PKEY_EC) {
                privateKey = params->CreateKey ();
                publicKey = privateKey->GetPublicKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        DHEKeyExchange::DHEKeyExchange (Params::Ptr params) :
                KeyExchange (ID::Empty),
                initiator (false) {
            DHEParams::Ptr dheParams =
                util::dynamic_refcounted_pointer_cast<DHEParams> (params);
            if (dheParams.Get () != 0) {
                id = dheParams->id;
                this->params = dheParams->params;
                salt = dheParams->salt;
                keyLength = dheParams->keyLength;
                messageDigest = dheParams->messageDigest;
                count = dheParams->count;
                keyId = dheParams->keyId;
                name = dheParams->name;
                description = dheParams->description;
                privateKey = this->params->CreateKey ();
                this->publicKey = privateKey->GetPublicKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr DHEKeyExchange::GetParams (
                AsymmetricKey::Ptr privateKey,
                const EVP_MD *md) const {
            Params::Ptr dheParams (
                new DHEParams (
                    id,
                    params,
                    salt,
                    keyLength,
                    messageDigest,
                    count,
                    keyId,
                    name,
                    description,
                    publicKey));
            if (privateKey.Get () != 0 && md != 0) {
                dheParams->CreateSignature (privateKey, md);
            }
            return dheParams;
        }

        namespace {
            util::Buffer GetSalt (
                    const std::vector<util::ui8> &salt,
                    const AsymmetricKey &publicKey1,
                    const AsymmetricKey &publicKey2) {
                util::Buffer buffer (
                    util::NetworkEndian,
                    util::Serializer::Size (salt) +
                    util::Serializable::Size (publicKey1) +
                    util::Serializable::Size (publicKey2));
                buffer << salt << publicKey1 << publicKey2;
                return buffer;
            }
        }

        SymmetricKey::Ptr DHEKeyExchange::DeriveSharedSymmetricKey (Params::Ptr params) const {
            DHEParams::Ptr dheParams =
                util::dynamic_refcounted_pointer_cast<DHEParams> (params);
            if (dheParams.Get () != 0) {
                EVP_PKEY_CTXPtr ctx (EVP_PKEY_CTX_new (privateKey->Get (), OpenSSLInit::engine));
                if (ctx.get () != 0) {
                    std::size_t secretLength = 0;
                    if (EVP_PKEY_derive_init (ctx.get ()) == 1 &&
                            EVP_PKEY_derive_set_peer (ctx.get (), dheParams->publicKey->Get ()) == 1 &&
                            EVP_PKEY_derive (ctx.get (), 0, &secretLength) == 1) {
                        util::SecureVector<util::ui8> secret (secretLength);
                        if (EVP_PKEY_derive (ctx.get (), &secret[0], &secretLength) == 1) {
                            util::Buffer salt = initiator ?
                                GetSalt (dheParams->salt, *publicKey, *dheParams->publicKey) :
                                GetSalt (dheParams->salt, *dheParams->publicKey, *publicKey);
                            return SymmetricKey::FromSecretAndSalt (
                                &secret[0],
                                secretLength,
                                salt.GetReadPtr (),
                                salt.GetDataAvailableForReading (),
                                dheParams->keyLength,
                                CipherSuite::GetOpenSSLMessageDigestByName (dheParams->messageDigest),
                                dheParams->count,
                                dheParams->keyId,
                                dheParams->name,
                                dheParams->description);
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

    } // namespace crypto
} // namespace thekogans
