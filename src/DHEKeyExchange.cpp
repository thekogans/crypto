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
            DHEKeyExchange::DHParams,
            1,
            util::SpinLock,
            16,
            util::DefaultAllocator::Global)

        std::size_t DHEKeyExchange::DHParams::Size () const {
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

        void DHEKeyExchange::DHParams::Read (
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

        void DHEKeyExchange::DHParams::Write (util::Serializer &serializer) const {
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
                key = params->CreateKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        DHEKeyExchange::DHEKeyExchange (Params::Ptr params) :
                KeyExchange (ID::Empty) {
            DHParams::Ptr dhParams =
                util::dynamic_refcounted_pointer_cast<DHParams> (params);
            if (dhParams.Get () != 0) {
                id = dhParams->id;
                this->params = dhParams->params;
                salt = dhParams->salt;
                keyLength = dhParams->keyLength;
                messageDigest = dhParams->messageDigest;
                count = dhParams->count;
                keyId = dhParams->keyId;
                name = dhParams->name;
                description = dhParams->description;
                key = this->params->CreateKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr DHEKeyExchange::GetParams () const {
            return Params::Ptr (
                new DHParams (
                    id,
                    params,
                    salt,
                    (util::ui32)keyLength,
                    messageDigest,
                    (util::ui32)count,
                    keyId,
                    name,
                    description,
                    key->GetPublicKey ()));
        }

        SymmetricKey::Ptr DHEKeyExchange::DeriveSharedSymmetricKey (Params::Ptr params) const {
            DHParams::Ptr dhParams =
                util::dynamic_refcounted_pointer_cast<DHParams> (params);
            if (dhParams.Get () != 0) {
                EVP_PKEY_CTXPtr ctx (EVP_PKEY_CTX_new (key->Get (), OpenSSLInit::engine));
                if (ctx.get () != 0) {
                    std::size_t secretLength = 0;
                    if (EVP_PKEY_derive_init (ctx.get ()) == 1 &&
                            EVP_PKEY_derive_set_peer (ctx.get (), dhParams->publicKey->Get ()) == 1 &&
                            EVP_PKEY_derive (ctx.get (), 0, &secretLength) == 1) {
                        util::SecureVector<util::ui8> secret (secretLength);
                        if (EVP_PKEY_derive (ctx.get (), &secret[0], &secretLength) == 1) {
                            return SymmetricKey::FromSecretAndSalt (
                                &secret[0],
                                secretLength,
                                !dhParams->salt.empty () ? &dhParams->salt[0] : 0,
                                dhParams->salt.size (),
                                dhParams->keyLength,
                                CipherSuite::GetOpenSSLMessageDigest (dhParams->messageDigest),
                                dhParams->count,
                                dhParams->keyId,
                                dhParams->name,
                                dhParams->description);
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
