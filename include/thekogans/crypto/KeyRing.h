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
        /// KeyRing is a collection of \see{Params}, \see{SymmetricKey} and \see{AsymmetricKey}
        /// suitable for use with a particular \see{CipherSuite}. KeyRings design makes it perfectly
        /// suitable for both duties of securing data on the wire as well as data at rest. In the
        /// former case, create a KeyRing, call KeyRing::Save and distribute it to the communicating
        /// peers. Have both peers call KeyRing::Load and use the master key to generate temporary
        /// session (active) keys. Once the session is over, destroy the KeyRing without calling
        /// KeyRing::Save. In the later case, create a KeyRing, use it to generate permanent
        /// encryption (active) keys, then call KeyRing::Save. Later call KeyRing::Load and use
        /// it to decrypt the data at rest.

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
            /// \see{Authenticator} \see{Params} map.
            ParamsMap authenticatorParamsMap;
            /// \brief
            /// \see{Authenticator} \see{AsymmetricKey} map.
            AsymmetricKeyMap authenticatorKeyMap;
            /// \brief
            /// \see{Cipher} master key.
            SymmetricKey::Ptr cipherMasterKey;
            /// \brief
            /// Convenient typedef for std::map<ID, SymmetricKey::Ptr>.
            typedef std::map<ID, SymmetricKey::Ptr> SymmetricKeyMap;
            /// \brief
            /// \see{Cipher} active \see{SymmetricKey} map.
            SymmetricKeyMap cipherActiveKeyMap;
            /// \brief
            /// Where active keys go to die.
            SymmetricKeyMap cipherRetiredKeyMap;
            /// \brief
            /// \see{MAC} \see{AsymmetricKey} map.
            AsymmetricKeyMap macKeyMap;
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
                const std::string &description = std::string ());
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
            /// Return the \see{Cipher} master key.
            /// \return \see{Cipher} master key.
            inline SymmetricKey::Ptr GetCipherMasterKey () const {
                return cipherMasterKey;
            }
            /// \brief
            /// Set the \see{Cipher} master key to the given key.
            /// \param[in] masterKey_ New \see{Cipher} master key to set.
            void SetCipherMasterKey (SymmetricKey::Ptr masterKey_);

            /// \brief
            /// Retrieve the \see{Cipher} \see{SymmetricKey} (master, active or retired)
            /// corresponding to the given \see{ID}.
            /// \param[in] keyId \see{ID} of \see{Cipher} \see{SymmetricKey} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return Master, active or retired \see{SymmetricKey} corresponding to the
            /// given \see{ID}. \see{Key::Ptr} () if not found.
            SymmetricKey::Ptr GetCipherKey (
                const ID &keyId,
                bool recursive = true) const;

            /// \brief
            /// Add a \see{Cipher} \see{SymmetricKey} to the ring.
            /// \param[in] key \see{Cipher} \see{SymmetricKey} to add.
            /// \return true = key added. false = A key with
            /// this id already exists in the ring.
            bool AddCipherActiveKey (SymmetricKey::Ptr key);
            /// \brief
            /// Given an active \see{Cipher} \see{SymmetricKey} \see{ID}, move the corresponding
            /// key to the retired key map.
            /// \param[in] keyId Active \see{Cipher} \see{SymmetricKey} \see{ID} to retire.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = retired, false = not found.
            bool RetireCipherActiveKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Given an active \see{Cipher} \see{SymmetricKey} \see{ID}, drop the corresponding key
            /// from the key ring.
            /// \param[in] keyId Active \see{Cipher} \see{SymmetricKey} \see{ID} to drop from the key ring.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropCipherActiveKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all active \see{Cipher} \see{SymmetricKey}s.
            /// \param[in] recursive true = descend down to sub rings.
            void DropCipherActiveKeys (bool recursive = true);
            /// \brief
            /// Given a retired \see{Cipher} \see{SymmetricKey} \see{ID}, drop the corresponding
            /// key from the key ring.
            /// \param[in] keyId Retired \see{Cipher} \see{SymmetricKey} \see{ID} to drop from the key ring.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropCipherRetiredKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all \see{Cipher} retired \see{SymmetricKey}s.
            /// \param[in] recursive descend down to sub rings.
            void DropCipherRetiredKeys (bool recursive = true);
            /// \brief
            /// Drop all \see{Cipher} keys. Master key is not affected.
            /// \param[in] recursive descend down to sub rings.
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
            /// Return the sub ring with the given id.
            /// \param[in] subringId Id of sub ring to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return Sub ring corresponding to the given subringId (Ptr () if not found).
            Ptr GetSubring (
                const ID &subringId,
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
            /// Drop all params, keys and sub rings.
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
            /// "CipherMasterKey"
            static const char * const TAG_CIPHER_MASTER_KEY;
            /// \brief
            /// "CipherActiveKeys"
            static const char * const TAG_CIPHER_ACTIVE_KEYS;
            /// \brief
            /// "CipherActiveKey"
            static const char * const TAG_CIPHER_ACTIVE_KEY;
            /// \brief
            /// "CipherRetiredKeys"
            static const char * const TAG_CIPHER_RETIRED_KEYS;
            /// \brief
            /// "CipherRetiredKey"
            static const char * const TAG_CIPHER_RETIRED_KEY;
            /// \brief
            /// "MACKeys"
            static const char * const TAG_MAC_KEYS;
            /// \brief
            /// "MACKey"
            static const char * const TAG_MAC_KEY;
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
