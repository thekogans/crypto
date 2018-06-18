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
#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/KeyExchange.h"

namespace thekogans {
    namespace crypto {

        std::size_t KeyExchange::Params::Size () const {
            return util::Serializer::Size (keyExchangeId);
        }

        void KeyExchange::Params::Read (
                const Header & /*header*/,
                util::Serializer &serializer) {
            serializer >> keyExchangeId;
        }

        void KeyExchange::Params::Write (util::Serializer &serializer) const {
            serializer << keyExchangeId;
        }

        std::size_t KeyExchange::DHParams::Size () const {
            return
                Params::Size () +
                util::Serializable::Size (*params) +
                util::Serializable::Size (*publicKey);
        }

        void KeyExchange::DHParams::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            serializer >> params >> publicKey;
        }

        void KeyExchange::DHParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer << *params << *publicKey;
        }

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (KeyExchange::DHParams, 1, 16)

        std::size_t KeyExchange::RSAParams::Size () const {
            return
                Params::Size () +
                util::Serializer::Size (keyId) +
                util::Serializer::Size (*buffer);
        }

        void KeyExchange::RSAParams::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            buffer.reset (new util::Buffer (util::NetworkEndian));
            serializer >> keyId >> *buffer;
        }

        void KeyExchange::RSAParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer << keyId << *buffer;
        }

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (KeyExchange::RSAParams, 1, 16)

        KeyExchange::KeyExchange (crypto::Params::Ptr params_) :
                params (params_) {
            util::i32 type = params->GetType ();
            if (type == EVP_PKEY_DH || type == EVP_PKEY_EC) {
                key = params->CreateKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::KeyExchange (
                AsymmetricKey::Ptr key_,
                util::ui32 secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                key (key_) {
            if (key.Get () != 0 && key->GetType () == EVP_PKEY_RSA && !key->IsPrivate () &&
                    secretLength > 0 && md != 0 && count > 0) {
                util::SecureVector<util::ui8> secret (secretLength);
                if (util::GlobalRandomSource::Instance ().GetBytes (
                        &secret[0], secretLength) == secretLength) {
                    symmetricKey = SymmetricKey::FromSecretAndSalt (
                        &secret[0],
                        secretLength,
                        salt,
                        saltLength,
                        keyLength,
                        md,
                        count,
                        id,
                        name,
                        description);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get %u random bytes for key.",
                        secretLength);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::KeyExchange (
                AsymmetricKey::Ptr key_,
                util::Buffer &buffer) :
                key (key_) {
            if (key.Get () != 0 && key->GetType () == EVP_PKEY_RSA && key->IsPrivate ()) {
                util::Buffer::UniquePtr symmetricKeyBuffer =
                    RSA::DecryptBuffer (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        key,
                        RSA_PKCS1_OAEP_PADDING,
                        true);
                SymmetricKey::Ptr symmetricKey;
                *symmetricKeyBuffer >> symmetricKey;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr KeyExchange::GetParams (const ID &keyExchangeId) const {
            util::i32 type = key->GetType ();
            if (type == EVP_PKEY_EC || type == EVP_PKEY_DH) {
                return Params::Ptr (
                    new DHParams (keyExchangeId, params, key->GetPublicKey ()));
            }
            assert (type == EVP_PKEY_RSA);
            util::SecureBuffer symmetricKeyBuffer (
                util::NetworkEndian,
                util::Serializable::Size (*symmetricKey));
            symmetricKeyBuffer << *symmetricKey;
            if (key->IsPrivate ()) {
                Authenticator authenticator (Authenticator::Sign, key);
                return Params::Ptr (
                    new RSAParams (
                        keyExchangeId,
                        key->GetId (),
                        authenticator.SignBuffer (
                            symmetricKeyBuffer.GetReadPtr (),
                            symmetricKeyBuffer.GetDataAvailableForReading ())));
            }
            return Params::Ptr (
                new RSAParams (
                    keyExchangeId,
                    key->GetId (),
                    RSA::EncryptBuffer (
                        symmetricKeyBuffer.GetReadPtr (),
                        symmetricKeyBuffer.GetDataAvailableForReading (),
                        key)));
        }

        SymmetricKey::Ptr KeyExchange::DeriveSharedSymmetricKey (
                Params::Ptr params,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (params.Get () != 0 && keyLength > 0 && md != 0) {
                util::i32 type = key->GetType ();
                if (type == EVP_PKEY_EC || type == EVP_PKEY_DH) {
                    EVP_PKEY_CTXPtr ctx (EVP_PKEY_CTX_new (key->Get (), OpenSSLInit::engine));
                    if (ctx.get () != 0) {
                        std::size_t secretLength = 0;
                        DHParams::Ptr dhParams =
                            util::dynamic_refcounted_pointer_cast<DHParams> (params);
                        if (EVP_PKEY_derive_init (ctx.get ()) == 1 &&
                                EVP_PKEY_derive_set_peer (ctx.get (), dhParams->publicKey->Get ()) == 1 &&
                                EVP_PKEY_derive (ctx.get (), 0, &secretLength) == 1) {
                            util::SecureVector<util::ui8> secret (secretLength);
                            if (EVP_PKEY_derive (ctx.get (), &secret[0], &secretLength) == 1) {
                                return SymmetricKey::FromSecretAndSalt (
                                    &secret[0],
                                    secretLength,
                                    salt,
                                    saltLength,
                                    keyLength,
                                    md,
                                    count,
                                    id,
                                    name,
                                    description);
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
                assert (type == EVP_PKEY_RSA);
                if (key->IsPrivate ()) {
                    return symmetricKey;
                }
                Authenticator authenticator (Authenticator::Verify, key);
                util::SecureBuffer symmetricKeyBuffer (
                    util::NetworkEndian,
                    util::Serializable::Size (*symmetricKey));
                symmetricKeyBuffer << *symmetricKey;
                RSAParams::Ptr rsaParams =
                    util::dynamic_refcounted_pointer_cast<RSAParams> (params);
                if (authenticator.VerifyBufferSignature (
                        symmetricKeyBuffer.GetReadPtr (),
                        symmetricKeyBuffer.GetDataAvailableForReading (),
                        rsaParams->buffer->GetReadPtr (),
                        rsaParams->buffer->GetDataAvailableForReading ())) {
                    return symmetricKey;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Key (%s) failed signature verification.",
                        symmetricKey->GetId ().ToString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
