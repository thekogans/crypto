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

#include <string>
#include <list>
#include <map>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Cipher.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyRing KeyRing.h thekogans/crypto/KeyRing.h
        ///
        /// \brief
        /// KeyRing is a collection of \see{Params}, \see{AsymmetricKey} and \see{SymmetricKey} and
        /// user data (\see{Serializable}) suitable for use with a particular \see{CipherSuite}.
        /// KeyRings design makes it perfectly suitable for both duties of securing data on the wire
        /// as well as data at rest. In the former case, create a KeyRing containing an appropriate
        /// \see{CipherSuite}, \see{KeyExchange} \see{Params} or \see{AsymmetricKey}s, \see{Authenticator}
        /// \see{Params} or \see{AsymmetricKey}, and user data (\see{Serializable}), call KeyRing::Save
        /// and distribute it to the communicating peers. Have both peers call KeyRing::Load and use
        /// the enclosed keys and parameters to authenticate each other and perform key exchange to
        /// generate temporary \see{Cipher} \see{SymmetricKey} session keys. Once the session is over,
        /// destroy the KeyRing without calling KeyRing::Save. In the later case, create a KeyRing, use
        /// it to generate permanent encryption keys, then call KeyRing::Save. Later call KeyRing::Load and
        /// use it to decrypt the data at rest. See encryptfile and decryptfile examples.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyRing : public Serializable {
            /// \brief
            /// KeyRing is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (KeyRing)

        private:
            /// \brief
            /// \see{CipherSuite} associated with this key ring.
            CipherSuite cipherSuite;
            /// \brief
            /// Convenient typedef for std::map<ID, Params::Ptr>.
            typedef std::map<ID, Params::Ptr> ParamsMap;
            /// \brief
            /// \see{KeyExchange} \see{Params} map.
            ParamsMap keyExchangeParamsMap;
            /// \brief
            /// Convenient typedef for std::map<ID, AsymmetricKeyMap::Ptr>.
            typedef std::map<ID, AsymmetricKey::Ptr> AsymmetricKeyMap;
            /// \brief
            /// \see{KeyExchange} \see{AsymmetricKey} map.
            AsymmetricKeyMap keyExchangeKeyMap;
            /// \brief
            /// Convenient typedef for std::map<ID, KeyExchange::Ptr>.
            typedef std::map<ID, KeyExchange::Ptr> KeyExchangeMap;
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
            /// Convenient typedef for std::pair<Authenticator::Op, ID>.
            typedef std::pair<Authenticator::Op, ID> AuthenticatorMapKey;
            /// \brief
            /// Convenient typedef for std::map<AuthenticatorMapKey, Authenticator::Ptr>.
            typedef std::map<AuthenticatorMapKey, Authenticator::Ptr> AuthenticatorMap;
            /// \brief
            /// \see{Authenticator} map.
            AuthenticatorMap authenticatorMap;
            /// \brief
            /// Convenient typedef for std::map<ID, SymmetricKey::Ptr>.
            typedef std::map<ID, SymmetricKey::Ptr> SymmetricKeyMap;
            /// \brief
            /// \see{Cipher} \see{SymmetricKey} map.
            SymmetricKeyMap cipherKeyMap;
            /// \brief
            /// Convenient typedef for std::map<ID, Cipher::Ptr>.
            typedef std::map<ID, Cipher::Ptr> CipherMap;
            /// \brief
            /// \see{Cipher} map.
            CipherMap cipherMap;
            /// \brief
            /// \see{MAC} \see{AsymmetricKey} map.
            AsymmetricKeyMap macKeyMap;
            /// \brief
            /// Convenient typedef for std::map<ID, MAC::Ptr>.
            typedef std::map<ID, MAC::Ptr> MACMap;
            /// \brief
            /// \see{MAC} map.
            MACMap macMap;
            /// \brief
            /// Convenient typedef for std::map<ID, Serializable::Ptr>.
            typedef std::map<ID, Serializable::Ptr> SerializableMap;
            /// \brief
            /// \see{MAC} map.
            SerializableMap userDataMap;
            /// \brief
            /// Convenient typedef for std::map<ID, Ptr>.
            typedef std::map<ID, Ptr> KeyRingMap;
            /// \brief
            /// Subrings hanging off this keyring.
            KeyRingMap subringsMap;

        public:
            /// \brief
            /// ctor.
            /// \param[in] cipherSuite_ \see{CipherSuite} associated with this key ring.
            /// \param[in] name Optional keyring name.
            /// \param[in] description Optional keyring description.
            KeyRing (
                const CipherSuite &cipherSuite_,
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Serializable (name, description),
                cipherSuite (cipherSuite_) {}
            /// \brief
            /// ctor.
            /// \param[in] buffer Buffer containing the serialized key ring.
            explicit KeyRing (util::Serializer &serializer);

            /// \brief
            /// Load a key ring from a file previously written with Save.
            /// \param[in] path File name to read the key ring from.
            /// \param[in] cipher Optional \see{Cipher} used to decrypt the file data.
            /// \param[in] associatedData Optional associated data (GCM mode only).
            /// \param[in] associatedDataLength Length of optional associated data.
            static Ptr Load (
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
            /// (Params::Ptr () if not found).
            Params::Ptr GetKeyExchangeParams (
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
                virtual bool operator () (const T &t) const throw () = 0;
            };
            /// \brief
            /// Return the \see{KeyExchange} \see{Params} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each keyExchangeParamsMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{KeyExchange} \see{Params} matching the given EqualityTest
            /// (Params::Ptr () if not found).
            Params::Ptr GetKeyExchangeParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a \see{KeyExchange} \see{Params} to this ring.
            /// \param[in] params \see{KeyExchange} \see{Params} to add.
            /// \return true = params added. false = A \see{Params} with
            /// this \see{ID} already exists in the ring.
            bool AddKeyExchangeParams (Params::Ptr params);
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
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetKeyExchangeKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{KeyExchange} \see{AsymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each keyExchangeKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{KeyExchange} \see{AsymmetricKey} matching the given EqualityTest
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetKeyExchangeKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{KeyExchange} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{KeyExchange} \see{AsymmetricKey}.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{KeyExchange} corresponding to the given keyId
            /// (KeyExchange::Ptr () if not found).
            KeyExchange::Ptr GetKeyExchange (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Add a \see{KeyExchange} \see{AsymmetricKey} to this ring.
            /// \param[in] key \see{KeyExchange} \see{AsymmetricKey} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddKeyExchangeKey (AsymmetricKey::Ptr key);
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
            /// Return the \see{Authenticator} \see{Params} with the given \see{ID}.
            /// \param[in] paramsId \see{ID} of \see{Authenticator} \see{Params} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Authenticator} \see{Params} corresponding to the given paramsId
            /// (Params::Ptr () if not found).
            Params::Ptr GetAuthenticatorParams (
                const ID &paramsId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} \see{Params} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each authenticatorParamsMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Authenticator} \see{Params} matching the given EqualityTest
            /// (Params::Ptr () if not found).
            Params::Ptr GetAuthenticatorParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a \see{Authenticator} \see{Params} to this ring.
            /// \param[in] params \see{Authenticator} \see{Params} to add.
            /// \return true = params added. false = A \see{Params} with
            /// this \see{ID} already exists in the ring.
            bool AddAuthenticatorParams (Params::Ptr params);
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
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetAuthenticatorKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} \see{AsymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each authenticatorKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Authenticator} \see{AsymmetricKey} matching the given EqualityTest
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetAuthenticatorKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Authenticator} with the given \see{Authenticator::Op} and \see{ID}.
            /// \param[in] op \see{Authenticator::Op}.
            /// \param[in] keyId \see{ID} of \see{Authenticator} \see{AsymmetricKey}.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Authenticator} corresponding to the given op and keyId
            /// (Authenticator::Ptr () if not found).
            Authenticator::Ptr GetAuthenticator (
                Authenticator::Op op,
                const ID &keyId,
                bool recursive);
            /// \brief
            /// Add a \see{Authenticator} \see{AsymmetricKey} to this ring.
            /// \param[in] key \see{Authenticator} \see{AsymmetricKey} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddAuthenticatorKey (AsymmetricKey::Ptr key);
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
            // (\see{Key::Ptr} () if not found).
            SymmetricKey::Ptr GetCipherKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{Cipher} \see{SymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each cipherKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Cipher} \see{SymmetricKey} matching the given EqualityTest
            /// (SymmetricKey::Ptr () if not found).
            SymmetricKey::Ptr GetCipherKey (
                const EqualityTest<SymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Retrieve the \see{Cipher} corresponding to the given key \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Cipher} key.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Cipher} corresponding to the given key \see{ID}
            /// (\see{Key::Ptr} () if not found).
            Cipher::Ptr GetCipher (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Add a \see{Cipher} \see{SymmetricKey} to the ring.
            /// \param[in] key \see{Cipher} \see{SymmetricKey} to add.
            /// \return true = key added. false = A key with
            /// this id already exists in the ring.
            bool AddCipherKey (SymmetricKey::Ptr key);
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
            /// Return the \see{MAC} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} \see{AsymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{MAC} \see{AsymmetricKey} corresponding to the given keyId
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetMACKey (
                const ID &keyId,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{MAC} \see{AsymmetricKey} matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each macKeyMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{MAC} \see{AsymmetricKey} matching the given EqualityTest
            /// (AsymmetricKey::Ptr () if not found).
            AsymmetricKey::Ptr GetMACKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Return the \see{MAC} with the given key \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} key.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{MAC} corresponding to the given keyId (MAC::Ptr () if not found).
            MAC::Ptr GetMAC (
                const ID &keyId,
                bool recursive);
            /// \brief
            /// Add a \see{MAC} \see{AsymmetricKey} to this ring.
            /// \param[in] key \see{MAC} \see{AsymmetricKey} to add.
            /// \return true = key added. false = A key with this \see{ID}
            /// already exists in the ring.
            bool AddMACKey (AsymmetricKey::Ptr key);
            /// \brief
            /// Drop a \see{MAC} \see{AsymmetricKey} with the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{MAC} \see{AsymmetricKey} to delete.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropMACKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{MAC} \see{AsymmetricKey}.
            /// \param[in] recursive true = descend down to sub rings.
            void DropAllMACKeys (bool recursive = true);

            /// \brief
            /// Return user data with the given \see{ID}.
            /// \param[in] id \see{ID} of user data to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return \see{Serializable} corresponding to the given id
            /// (Serializable::Ptr () if not found).
            Serializable::Ptr GetUserData (
                const ID &id,
                bool recursive) const;
            /// \brief
            /// Return user data matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each userDataMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First \see{Serializable} matching the given EqualityTest
            /// (Serializable::Ptr () if not found).
            Serializable::Ptr GetUserData (
                const EqualityTest<Serializable> &equalityTest,
                bool recursive) const;
            /// \brief
            /// Add user data to this ring.
            /// \param[in] userData \see{Serializable} to add.
            /// \return true = user data added. false = user data with this \see{ID}
            /// already exists in the ring.
            bool AddUserData (Serializable::Ptr userData);
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
            /// \return Sub ring corresponding to the given subringId (Ptr () if not found).
            Ptr GetSubring (
                const ID &subringId,
                bool recursive = true) const;
            /// \brief
            /// Return the sub ring matching the given EqualityTest.
            /// \param[in] equalityTest EqualityTest to call for each subringMap item.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return First Sub ring matching the given EqualityTest (Ptr () if not found).
            Ptr GetSubring (
                const EqualityTest<KeyRing> &equalityTest,
                bool recursive = true) const;
            /// \brief
            /// Add a sub ring to this ring.
            /// \param[in] subring Sub ring to add.
            /// \return true = sub ring added. false = A sub ring with
            /// this id already exists in the ring.
            bool AddSubring (Ptr subring);
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

            /// \brief
            /// Return the serialized keyring size.
            /// \param[in] includeType true = include key's type in size calculation.
            /// \return Serialized keyring size.
            virtual std::size_t Size (bool includeType = true) const;

            /// \brief
            /// Save the key ring to a serializer.
            /// \param[in] serializer Serializer to write the keyring to.
            /// \param[in] includeType true = Serialize keyrings's type
            /// to be used by \see{Serializable::Get}.
            virtual void Serialize (
                util::Serializer &serializer,
                bool includeType = true) const;

        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// Dump the key ring to std::cout.
            /// ********************** WARNING **********************
            /// This is antithetical to security which is precisely
            /// why it should be used only for testing and turned off
            /// when building for production.
            /// *****************************************************
            void Dump () const;

        private:
            /// \brief
            /// "KeyRing"
            static const char * const TAG_KEY_RING;
            /// \brief
            /// "Id"
            static const char * const ATTR_ID;
            /// \brief
            /// "Name"
            static const char * const ATTR_NAME;
            /// \brief
            /// "Description"
            static const char * const ATTR_DESCRIPTION;
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
            /// Return the XML representation of a key ring.
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of a key ring.
            std::string ToString (
                util::ui32 indentationLevel = 0,
                const char *tagName = TAG_KEY_RING) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)

            /// \brief
            /// KeyRing is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (KeyRing)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyRing_h)
