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

#if !defined (__thekogans_crypto_KeyRing_h)
#define __thekogans_crypto_KeyRing_h

#include <cstddef>
#include <string>
#include <map>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/crypto/RSAKeyExchange.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/crypto/MAC.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyRing KeyRing.h thekogans/crypto/KeyRing.h
        ///
        /// \brief
        /// KeyRing is a container for \see{Params}, \see{AsymmetricKey}, \see{SymmetricKey} and
        /// user data (\see{Serializable}) suitable for use with a particular \see{CipherSuite}.
        /// KeyRings design makes it perfectly suitable for both duties of securing data on the
        /// wire as well as data at rest. In the former case, create a KeyRing containing an
        /// appropriate \see{CipherSuite}, \see{KeyExchange} \see{Params} or \see{AsymmetricKey}s,
        /// \see{Authenticator} \see{Params} or \see{AsymmetricKey}, and user data (\see{Serializable}),
        /// call KeyRing::Save and distribute it to the communicating peers. Have both peers call
        /// KeyRing::Load and use the enclosed keys and parameters to authenticate each other and
        /// perform key exchange to generate temporary \see{Cipher} \see{SymmetricKey} session keys.
        /// Once the session is over, destroy the KeyRing without calling KeyRing::Save. In the
        /// later case, create a KeyRing, use it to generate permanent encryption keys, then call
        /// KeyRing::Save. Later call KeyRing::Load and use it to decrypt the data at rest. See
        /// encryptfile and decryptfile examples.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyRing : public Serializable {
            /// \brief
            /// KeyRing is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (KeyRing)

        private:
            /// \brief
            /// \see{CipherSuite} associated with this key ring.
            CipherSuite cipherSuite;
            /// \brief
            /// Alias for std::map<ID, Params::SharedPtr>.
            using ParamsMap = std::map<ID, Params::SharedPtr>;
            /// \brief
            /// \see{KeyExchange} \see{Params} map.
            ParamsMap keyExchangeParamsMap;
            /// \brief
            /// Alias for std::map<ID, AsymmetricKeyMap::SharedPtr>.
            using AsymmetricKeyMap = std::map<ID, AsymmetricKey::SharedPtr>;
            /// \brief
            /// \see{KeyExchange} \see{AsymmetricKey} map.
            AsymmetricKeyMap keyExchangeKeyMap;
            /// \brief
            /// Alias for std::map<ID, KeyExchange::SharedPtr>.
            using KeyExchangeMap = std::map<ID, KeyExchange::SharedPtr>;
            /// \brief
            /// \see{KeyExchange} map.
            KeyExchangeMap keyExchangeMap;
            /// \brief
            /// \see{Authenticator} \see{Params} map.
            ParamsMap authenticatorParamsMap;
            /// \brief
            /// \see{Authenticator} \see{AsymmetricKey} map.
            AsymmetricKeyMap authenticatorKeyMap;
            /// \brief
            /// Alias for std::map<ID, Authenticator::SharedPtr>.
            using AuthenticatorMap = std::map<ID, Authenticator::SharedPtr>;
            /// \brief
            /// \see{Authenticator} map.
            AuthenticatorMap authenticatorMap;
            /// \brief
            /// Alias for std::map<ID, SymmetricKey::SharedPtr>.
            using SymmetricKeyMap = std::map<ID, SymmetricKey::SharedPtr>;
            /// \brief
            /// \see{Cipher} \see{SymmetricKey} map.
            SymmetricKeyMap cipherKeyMap;
            /// \brief
            /// Alias for std::map<ID, Cipher::SharedPtr>.
            using CipherMap = std::map<ID, Cipher::SharedPtr>;
            /// \brief
            /// \see{Cipher} map.
            CipherMap cipherMap;
            /// \brief
            /// \see{MAC} \see{SymmetricKeyMap} map.
            SymmetricKeyMap macKeyMap;
            /// \brief
            /// Alias for std::map<ID, MAC::SharedPtr>.
            using MACMap = std::map<ID, MAC::SharedPtr>;
            /// \brief
            /// \see{MAC} map.
            MACMap macMap;
            /// \brief
            /// Alias for std::map<ID, Serializable::SharedPtr>.
            using SerializableMap = std::map<ID, Serializable::SharedPtr>;
            /// \brief
            /// \see{Serializable} map.
            SerializableMap userDataMap;
            /// \brief
            /// Alias for std::map<ID, SharedPtr>.
            using KeyRingMap = std::map<ID, SharedPtr>;
            /// \brief
            /// Subrings hanging off this key ring.
            KeyRingMap subringMap;

        public:
            /// \brief
            /// ctor.
            /// \param[in] cipherSuite_ \see{CipherSuite} associated with this key ring.
            /// \param[in] id Optional key ring id.
            /// \param[in] name Optional key ring name.
            /// \param[in] description Optional key ring description.
            KeyRing (
                const CipherSuite &cipherSuite_ = CipherSuite::Strongest,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Serializable (id, name, description),
                cipherSuite (cipherSuite_) {}

            /// \brief
            /// Load a key ring from a file previously written with Save.
            /// \param[in] path File name to read the key ring from.
            /// \param[in] cipher Optional \see{Cipher} used to decrypt the file data.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            static SharedPtr Load (
                const std::string &path,
                Cipher *cipher = 0,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0);
            /// \brief
            /// Save the key ring to a file.
            /// \param[in] path File name to save the key ring to.
            /// \param[in] cipher Optional \see{Cipher} used to encrypt the file data.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            void Save (
                const std::string &path,
                Cipher *cipher = 0,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0);

            /// \brief
            /// Return the \see{CipherSuite} associated with this key ring.
            /// \return \see{CipherSuite} associated with this key ring.
            inline const CipherSuite &GetCipherSuite () const {
                return cipherSuite;
            }

            /// \brief
            /// Return the \see{KeyExchange} \see{Params} with the given \see{ID}.
            /// \param[in] paramsId \see{ID} of \see{KeyExchange} \see{Params} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange} \see{Params} corresponding to the given paramsId
            /// (nullptr if not found).
            Params::SharedPtr GetKeyExchangeParams (
                const ID &paramsId,
                bool recursive = true) const;
            /// \struct KeyRing::EqualityTest KeyRing.h thekogans/crypto/KeyRing.h
            ///
            /// \brief
            /// Equality test template. Use it to locate various parameters, keys and key rings.
            template<typename T>
            struct EqualityTest {
                /// \brief
                /// dtor.
                virtual ~EqualityTest () {}

                /// \brief
                /// Reimplement this function to test for equality.
                /// \param[in] t Instance to test for equality.
                /// \return true == equal.
                virtual bool operator () (const T & /*t*/) const throw () = 0;
            };
            /// \brief
            /// Return the \see{KeyExchange} \see{Params} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each keyExchangeParamsMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{KeyExchange} \see{Params} matching the given EqualityTest
            /// (nullptr if not found).
            Params::SharedPtr GetKeyExchangeParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return randomly chosen \see{KeyExchange} \see{Params}.
            /// \return Randomly chosen \see{KeyExchange} \see{Params}.
            Params::SharedPtr GetRandomKeyExchangeParams () const;
            /// \brief
            /// Add a \see{KeyExchange} \see{Params} to this ring.
            /// \param[in] params \see{KeyExchange} \see{Params} to add.
            /// \return true = params added. false = A \see{Params} with
            /// this \see{ID} already exists in the ring.
            bool AddKeyExchangeParams (Params::SharedPtr params);
            /// \brief
            /// Drop a \see{KeyExchange} \see{Params} with the given \see{ID}.
            /// \param[in] paramsId \see{ID} of \see{KeyExchange} \see{Params} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropKeyExchangeParams (
                const ID &paramsId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{KeyExchange} \see{Params}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllKeyExchangeParams (bool recursive = true);

            /// \brief
            /// Return the \see{KeyExchange} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{KeyExchange} \see{AsymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange} \see{AsymmetricKey} corresponding to the given keyId
            /// (nullptr if not found).
            AsymmetricKey::SharedPtr GetKeyExchangeKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{KeyExchange} \see{AsymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each keyExchangeKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{KeyExchange} \see{AsymmetricKey} matching the given EqualityTest
            /// (nullptr if not found).
            AsymmetricKey::SharedPtr GetKeyExchangeKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a \see{KeyExchange} \see{AsymmetricKey} to this ring.
            /// \param[in] key \see{KeyExchange} \see{AsymmetricKey} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddKeyExchangeKey (AsymmetricKey::SharedPtr key);
            /// \brief
            /// Drop a \see{KeyExchange} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{KeyExchange} \see{AsymmetricKey} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropKeyExchangeKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{KeyExchange} \see{AsymmetricKey}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllKeyExchangeKeys (bool recursive = true);

            /// \brief
            /// Create a \see{KeyExchange} instance (\see{DHEKeyExchange} or \see{RSAKeyExchange}).
            /// If \see{CipherSuite} key exchange is [EC]DHE, paramsOrKeyId represents a \see{DH}
            /// or a \see{EC} \see{Params} used to create an ephemeral \see{DH} \see{AsymmetricKey}.
            /// If paramsOrKeyId is \see{ID::Empty}, random params are used.
            /// If \see{CipherSuite} key exchange is \see{RSA}, paramsOrKeyId represents a public
            /// \see{RSA} \see{AsymmetricKey} used to encrypt a random \see{SymmetricKey}.
            /// For \see{RSA} key exchange, paramsOrKeyId cannot be \see{ID::Empty}.
            /// This method is used by the initiator (client) of the key exchange.
            /// \param[in] paramsOrKeyId \see{ID} of \see{Params} or \see{AsymmetricKey}.
            /// \param[in] secretLength Length of random data to use for \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] keyId Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange::SharedPtr} corresponding to the given paramsOrKeyId
            /// (\see{KeyExchange::SharedPtr} () if not found).
            KeyExchange::SharedPtr AddKeyExchange (
                const ID &paramsOrKeyId,
                std::size_t secretLength = RSAKeyExchange::DEFAULT_SECRET_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t count = 1,
                const ID &keyId = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string (),
                bool recursive = true);
            /// \brief
            /// Create a \see{KeyExchange} based on the given \see{KeyExchange::Params}.
            /// This method is used by the receiver (server) of the key exchange request.
            /// VERY IMPORTANT: \see{RSAKeyExchange} private \see{AsymmetricKey} will be
            /// located using \see{RSAKeyExchange::RSAParams::keyId}. Recall that this
            /// key id came from AddKeyExchange::paramsOrKeyId, which was the id of the
            /// public \see{AsymmetricKey} used to initiate the key exchange. This means
            /// that for \see{RSA} \see{AsymmetricKey} keys, both private and public keys
            /// must have the same id. You can accomplish this like this:
            /// \code{.cpp}
            /// using namespace thekogans;
            /// crypto::AsymmetricKey::SharedPtr privateKey = crypto::RSA:CreateKey (bits);
            /// crypto::AsymmetricKey::SharedPtr publicKey = privateKey->GetPublicKey (privateKey->GetId ());
            /// \endcode
            /// \param[in] params \see{KeyExchange::Params::SharedPtr} returned by AddKeyExchange.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange::SharedPtr} corresponding to the given params.
            KeyExchange::SharedPtr CreateKeyExchange (
                KeyExchange::Params::SharedPtr params,
                bool recursive = true);
            /// \brief
            /// Return the previously created \see{KeyExchange} by AddKeyExchange above.
            /// This method is used by the key exchange initiator (client) after receiving
            /// the server's \see{KeyExchange::Params}.
            /// NOTE: This method removes the \see{KeyExchange} identified by the given
            /// keyExchangeId from the key ring before returning it.
            /// \param[in] keyExchangeId \see{KeyExchange::keyExchangeId}.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange} corresponding to the given keyExchangeId.
            KeyExchange::SharedPtr GetKeyExchange (
                const ID &keyExchangeId,
                bool recursive = true);

            /// \brief
            /// Return the \see{Authenticator} \see{Params} with the given \see{ID}.
            /// \param[in] paramsId \see{ID} of \see{Authenticator} \see{Params} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Authenticator} \see{Params} corresponding to the given paramsId
            /// (nullptr if not found).
            Params::SharedPtr GetAuthenticatorParams (
                const ID &paramsId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} \see{Params} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each authenticatorParamsMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Authenticator} \see{Params} matching the given EqualityTest
            /// (nullptr if not found).
            Params::SharedPtr GetAuthenticatorParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a \see{Authenticator} \see{Params} to this ring.
            /// \param[in] params \see{Authenticator} \see{Params} to add.
            /// \return true = params added. false = A \see{Params} with
            /// this \see{ID} already exists in the ring.
            bool AddAuthenticatorParams (Params::SharedPtr params);
            /// \brief
            /// Drop a \see{Authenticator} \see{Params} with the given \see{ID}.
            /// \param[in] paramsId \see{ID} of \see{Authenticator} \see{Params} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropAuthenticatorParams (
                const ID &paramsId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{Authenticator} \see{Params}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllAuthenticatorParams (bool recursive = true);

            /// \brief
            /// Return the \see{Authenticator} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Authenticator} \see{AsymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Authenticator} \see{AsymmetricKey} corresponding to the given keyId
            /// (nullptr if not found).
            AsymmetricKey::SharedPtr GetAuthenticatorKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} \see{AsymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each authenticatorKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Authenticator} \see{AsymmetricKey} matching the given EqualityTest
            /// (nullptr if not found).
            AsymmetricKey::SharedPtr GetAuthenticatorKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Authenticator} \see{AsymmetricKey}.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Authenticator} corresponding to the given op and keyId
            /// (nullptr if not found).
            Authenticator::SharedPtr GetAuthenticator (
                const ID &keyId,
                bool recursive);
            /// \brief
            /// Add a \see{Authenticator} \see{AsymmetricKey} to this ring.
            /// \param[in] key \see{Authenticator} \see{AsymmetricKey} to add.
            /// \param[in] authenticator Optional \see{Authenticator} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddAuthenticatorKey (
                AsymmetricKey::SharedPtr key,
                Authenticator::SharedPtr authenticator = nullptr);
            /// \brief
            /// Drop a \see{Authenticator} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Authenticator} \see{AsymmetricKey} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropAuthenticatorKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{Authenticator} \see{AsymmetricKey}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllAuthenticatorKeys (bool recursive = true);

            /// \brief
            /// Retrieve the \see{Cipher} \see{SymmetricKey} corresponding to the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Cipher} \see{SymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Cipher} \see{SymmetricKey} corresponding to the given \see{ID}
            /// (\see{SymmetricKey::SharedPtr} () if not found).
            SymmetricKey::SharedPtr GetCipherKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Cipher} \see{SymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each cipherKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Cipher} \see{SymmetricKey} matching the given EqualityTest
            /// (nullptr if not found).
            SymmetricKey::SharedPtr GetCipherKey (
                const EqualityTest<SymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Retrieve the \see{Cipher} corresponding to the given key \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Cipher} key.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Cipher} corresponding to the given key \see{ID}
            /// (\see{Cipher::SharedPtr} () if not found).
            Cipher::SharedPtr GetCipher (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Return a \see{Cipher} based on randomly chosen \see{SymmetricKey}.
            /// NOTE: This is a special purpose method meant to be used by communicating
            /// peers that used \see{KeyExchange} to establish shared keys. The sending
            /// peer uses this method to select keys at random to encrypt packets on the
            /// wire using \see{Cipher::EncryptAndFrame}. The receiving peer uses the
            /// \see{FrameHeader::keyId} to retrieve it's key to decrypt the packet.
            /// This way the peers can rotate keys (for every packet if need be) for
            /// better security.
            /// WARNING: This method runs in O(cipherKeyMap.size ()).
            /// \return \see{Cipher} based on randomly chosen \see{SymmetricKey}.
            Cipher::SharedPtr GetRandomCipher ();
            /// \brief
            /// Add a \see{Cipher} \see{SymmetricKey} to the ring.
            /// \param[in] key \see{Cipher} \see{SymmetricKey} to add.
            /// \param[in] cipher Optional \see{Cipher} to add.
            /// \return true = key added. false = A key with
            /// this id already exists in the ring.
            bool AddCipherKey (
                SymmetricKey::SharedPtr key,
                Cipher::SharedPtr cipher = nullptr);
            /// \brief
            /// Given a \see{Cipher} \see{SymmetricKey} \see{ID}, drop the corresponding key
            /// from the key ring.
            /// \param[in] keyId \see{Cipher} \see{SymmetricKey} \see{ID} to drop from the key ring.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropCipherKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all active \see{Cipher} \see{SymmetricKey}s.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllCipherKeys (bool recursive = true);

            /// \brief
            /// Return the \see{MAC} \see{SymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} \see{SymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{MAC} \see{SymmetricKey} corresponding to the given keyId
            /// (nullptr if not found).
            SymmetricKey::SharedPtr GetMACKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{MAC} \see{SymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each macKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{MAC} \see{SymmetricKey} matching the given EqualityTest
            /// (nullptr if not found).
            SymmetricKey::SharedPtr GetMACKey (
                const EqualityTest<SymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{MAC} with the given key \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} key.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{MAC} corresponding to the given keyId (nullptr if not found).
            MAC::SharedPtr GetMAC (
                const ID &keyId,
                bool recursive);
            /// \brief
            /// Add a \see{MAC} \see{SymmetricKey} to this ring.
            /// \param[in] key \see{MAC} \see{SymmetricKey} to add.
            /// \param[in] mac Optional \see{MAC} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddMACKey (
                SymmetricKey::SharedPtr key,
                MAC::SharedPtr mac = nullptr);
            /// \brief
            /// Drop a \see{MAC} \see{SymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} \see{SymmetricKey} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropMACKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{MAC} \see{SymmetricKey}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllMACKeys (bool recursive = true);

            /// \brief
            /// Return user data with the given \see{ID}.
            /// \param[in] id \see{ID} of user data to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Serializable} corresponding to the given id
            /// (nullptr if not found).
            Serializable::SharedPtr GetUserData (
                const ID &id,
                bool recursive) const;
            /// \brief
            /// Return user data matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each userDataMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Serializable} matching the given EqualityTest
            /// (nullptr if not found).
            Serializable::SharedPtr GetUserData (
                const EqualityTest<Serializable> &equalityTest,
                bool recursive) const;
            /// \brief
            /// Add user data to this ring.
            /// \param[in] userData \see{Serializable} to add.
            /// \return true = user data added. false = user data with this \see{ID}
            /// already exists in the ring.
            bool AddUserData (Serializable::SharedPtr userData);
            /// \brief
            /// Drop user data with the given \see{ID}.
            /// \param[in] id \see{ID} of user data to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropUserData (
                const ID &id,
                bool recursive);
            /// \brief
            /// Drop all user data.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllUserData (bool recursive);

            /// \brief
            /// Return the sub ring with the given id.
            /// \param[in] subringId Id of sub ring to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return Sub ring corresponding to the given subringId (nullptr if not found).
            SharedPtr GetSubring (
                const ID &subringId,
                bool recursive = true) const;
            /// \brief
            /// Return the sub ring matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each subringMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First Sub ring matching the given EqualityTest (nullptr if not found).
            SharedPtr GetSubring (
                const EqualityTest<KeyRing> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a sub ring to this ring.
            /// \param[in] subring Sub ring to add.
            /// \return true = sub ring added. false = A sub ring with
            /// this id already exists in the ring.
            bool AddSubring (SharedPtr subring);
            /// \brief
            /// Drop a sub ring with the given id.
            /// \param[in] subringId Id of sub ring to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropSubring (
                const ID &subringId,
                bool recursive = true);
            /// \brief
            /// Drop all sub rings.
            void DropAllSubrings ();

            /// \brief
            /// Drop all params, keys, user data and sub rings.
            void Clear ();

            // Serializable
            /// \brief
            /// Return the serialized key ring size.
            /// \return Serialized key ring size.
            virtual std::size_t Size () const noexcept override;

            /// \brief
            /// Read the key ring from the given serializer.
            /// \param[in] header \see{util::Serializable::BinHeader}.
            /// \param[in] serializer \see{util::Serializer} to read the key ring from.
            virtual void Read (
                const BinHeader &header,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the key ring to the given serializer.
            /// \param[in] serializer \see{util::Serializer} to write the key ring to.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// "KeyRing"
            static const char * const TAG_KEY_RING;
            /// \brief
            /// "CipherSuite"
            static const char * const ATTR_CIPHER_SUITE;
            /// \brief
            /// "KeyExchangeParams"
            static const char * const TAG_KEY_EXCHANGE_PARAMS;
            /// \brief
            /// "KeyExchangeParam"
            static const char * const TAG_KEY_EXCHANGE_PARAM;
            /// \brief
            /// "KeyExchangeKeys"
            static const char * const TAG_KEY_EXCHANGE_KEYS;
            /// \brief
            /// "KeyExchangeKey"
            static const char * const TAG_KEY_EXCHANGE_KEY;
            /// \brief
            /// "AuthenticatorParams"
            static const char * const TAG_AUTHENTICATOR_PARAMS;
            /// \brief
            /// "AuthenticatorParam"
            static const char * const TAG_AUTHENTICATOR_PARAM;
            /// \brief
            /// "AuthenticatorKeys"
            static const char * const TAG_AUTHENTICATOR_KEYS;
            /// \brief
            /// "AuthenticatorKey"
            static const char * const TAG_AUTHENTICATOR_KEY;
            /// \brief
            /// "CipherKeys"
            static const char * const TAG_CIPHER_KEYS;
            /// \brief
            /// "CipherKey"
            static const char * const TAG_CIPHER_KEY;
            /// \brief
            /// "MACKeys"
            static const char * const TAG_MAC_KEYS;
            /// \brief
            /// "MACKey"
            static const char * const TAG_MAC_KEY;
            /// \brief
            /// "UserDatas"
            static const char * const TAG_USER_DATAS;
            /// \brief
            /// "UserData"
            static const char * const TAG_USER_DATA;
            /// \brief
            /// "SubRings"
            static const char * const TAG_SUB_RINGS;
            /// \brief
            /// "SubRing"
            static const char * const TAG_SUB_RING;

            /// \brief
            /// Read the Serializable from an XML DOM.
            /// \param[in] header \see{util::Serializable::TextHeader}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader &header,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write the Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader &header,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;

            /// \brief
            /// KeyRing is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (KeyRing)
        };

        /// \brief
        /// Implement KeyRing extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (KeyRing)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement KeyRing value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::KeyRing)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyRing_h)
