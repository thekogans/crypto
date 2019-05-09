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

#include <cassert>
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/DefaultAllocator.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/RSAKeyExchange.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            RSAKeyExchange::RSAParams,
            1,
            util::SpinLock,
            16,
            util::DefaultAllocator::Global)

        void RSAKeyExchange::RSAParams::CreateSignature (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest) {
            if (privateKey.Get () != 0 && messageDigest.Get () != 0) {
                util::Buffer paramsBuffer (
                    util::NetworkEndian,
                    util::Serializer::Size (id) +
                    util::Serializer::Size (keyId) +
                    util::Serializer::Size (buffer));
                paramsBuffer << id << keyId << buffer;
                Authenticator authenticator (privateKey, messageDigest);
                signature = authenticator.SignBuffer (
                    paramsBuffer.GetReadPtr (),
                    paramsBuffer.GetDataAvailableForReading ()).Tovector ();
                signatureKeyId = privateKey->GetId ();
                signatureMessageDigestName = messageDigest->GetName ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool RSAKeyExchange::RSAParams::ValidateSignature (
                AsymmetricKey::Ptr publicKey,
                MessageDigest::Ptr messageDigest) {
            if (publicKey.Get () != 0 && messageDigest.Get () != 0 &&
                    publicKey->GetId () == signatureKeyId &&
                    messageDigest->GetName () == signatureMessageDigestName) {
                if (!signature.empty ()) {
                    util::Buffer paramsBuffer (
                        util::NetworkEndian,
                        util::Serializer::Size (id) +
                        util::Serializer::Size (keyId) +
                        util::Serializer::Size (buffer));
                    paramsBuffer << id << keyId << buffer;
                    Authenticator authenticator (publicKey, messageDigest);
                    return authenticator.VerifyBufferSignature (
                        paramsBuffer.GetReadPtr (),
                        paramsBuffer.GetDataAvailableForReading (),
                        signature.data (),
                        signature.size ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Params (%s) are not signed.",
                        id.ToHexString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t RSAKeyExchange::RSAParams::Size () const {
            return
                Params::Size () +
                util::Serializer::Size (keyId) +
                util::Serializer::Size (buffer);
        }

        void RSAKeyExchange::RSAParams::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            serializer >> keyId >> buffer;
        }

        void RSAKeyExchange::RSAParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer << keyId << buffer;
        }

        const char * const RSAKeyExchange::RSAParams::ATTR_KEY_ID = "KeyId";
        const char * const RSAKeyExchange::RSAParams::ATTR_BUFFER = "Buffer";

        void RSAKeyExchange::RSAParams::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            Params::Read (header, node);
            keyId = ID::FromHexString (node.attribute (ATTR_KEY_ID).value ());
            buffer = util::HexDecodestring (node.attribute (ATTR_BUFFER).value ());
        }

        void RSAKeyExchange::RSAParams::Write (pugi::xml_node &node) const {
            Params::Write (node);
            node.append_attribute (ATTR_KEY_ID).set_value (keyId.ToHexString ().c_str ());
            node.append_attribute (ATTR_BUFFER).set_value (util::HexEncodeBuffer (buffer.data (), buffer.size ()).c_str ());
        }

        void RSAKeyExchange::RSAParams::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            Params::Read (header, object);
            keyId = ID::FromHexString (object.GetValue (ATTR_KEY_ID)->ToString ());
            buffer = util::HexDecodestring (object.GetValue (ATTR_BUFFER)->ToString ());
        }

        void RSAKeyExchange::RSAParams::Write (util::JSON::Object &object) const {
            Params::Write (object);
            object.AddString (ATTR_KEY_ID, keyId.ToHexString ());
            object.AddString (ATTR_BUFFER, util::HexEncodeBuffer (buffer.data (), buffer.size ()));
        }

        RSAKeyExchange::RSAKeyExchange (
                const ID &id,
                AsymmetricKey::Ptr key_,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &keyId,
                const std::string &keyName,
                const std::string &keyDescription) :
                KeyExchange (id),
                key (key_) {
            if (key.Get () != 0 && key->GetKeyType () == OPENSSL_PKEY_RSA && !key->IsPrivate () &&
                    secretLength > 0 && md != 0 && count > 0) {
                util::SecureVector<util::ui8> secret (secretLength);
                if (util::GlobalRandomSource::Instance ().GetBytes (
                        secret.data (), secretLength) == secretLength) {
                    symmetricKey = SymmetricKey::FromSecretAndSalt (
                        secret.data (),
                        secretLength,
                        salt,
                        saltLength,
                        keyLength,
                        md,
                        count,
                        keyId,
                        keyName,
                        keyDescription);
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

        RSAKeyExchange::RSAKeyExchange (
                AsymmetricKey::Ptr key_,
                Params::Ptr params) :
                KeyExchange (ID::Empty),
                key (key_) {
            RSAParams::Ptr rsaParams =
                util::dynamic_refcounted_pointer_cast<RSAParams> (params);
            if (key.Get () != 0 && key->GetKeyType () == OPENSSL_PKEY_RSA && key->IsPrivate () &&
                    rsaParams.Get () != 0) {
                id = rsaParams->id;
                util::Buffer symmetricKeyBuffer =
                    RSADecrypt (
                        rsaParams->buffer.data (),
                        rsaParams->buffer.size (),
                        key,
                        RSA_PKCS1_OAEP_PADDING,
                        true);
                symmetricKeyBuffer >> symmetricKey;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr RSAKeyExchange::GetParams (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest) const {
            Params::Ptr rsaParams;
            util::SecureBuffer symmetricKeyBuffer (
                util::NetworkEndian,
                util::Serializable::Size (*symmetricKey));
            symmetricKeyBuffer << *symmetricKey;
            if (key->IsPrivate ()) {
                Authenticator authenticator (key, MessageDigest::Ptr (new MessageDigest));
                rsaParams.Reset (
                    new RSAParams (
                        id,
                        key->GetId (),
                        authenticator.SignBuffer (
                            symmetricKeyBuffer.GetReadPtr (),
                            symmetricKeyBuffer.GetDataAvailableForReading ()).Tovector ()));
            }
            else {
                rsaParams.Reset (
                    new RSAParams (
                        id,
                        key->GetId (),
                        RSAEncrypt (
                            symmetricKeyBuffer.GetReadPtr (),
                            symmetricKeyBuffer.GetDataAvailableForReading (),
                            key).Tovector ()));
            }
            if (privateKey.Get () != 0 && messageDigest.Get () != 0) {
                rsaParams->CreateSignature (privateKey, messageDigest);
            }
            return rsaParams;
        }

        SymmetricKey::Ptr RSAKeyExchange::DeriveSharedSymmetricKey (Params::Ptr params) const {
            assert (symmetricKey.Get () != 0);
            if (!key->IsPrivate ()) {
                RSAParams::Ptr rsaParams =
                    util::dynamic_refcounted_pointer_cast<RSAParams> (params);
                if (rsaParams.Get () != 0) {
                    util::SecureBuffer symmetricKeyBuffer (
                        util::NetworkEndian,
                        util::Serializable::Size (*symmetricKey));
                    symmetricKeyBuffer << *symmetricKey;
                    Authenticator authenticator (key, MessageDigest::Ptr (new MessageDigest));
                    if (!authenticator.VerifyBufferSignature (
                            symmetricKeyBuffer.GetReadPtr (),
                            symmetricKeyBuffer.GetDataAvailableForReading (),
                            rsaParams->buffer.data (),
                            rsaParams->buffer.size ())) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Key (%s) failed signature verification.",
                            symmetricKey->GetId ().ToHexString ().c_str ());
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            return symmetricKey;
        }

    } // namespace crypto
} // namespace thekogans
