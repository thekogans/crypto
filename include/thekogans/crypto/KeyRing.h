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
#include "thekogans/util/Heap.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"
#include "thekogans/crypto/Key.h"
#include "thekogans/crypto/Cipher.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyRing KeyRing.h thekogans/crypto/KeyRing.h
        ///
        /// \brief
        /// KeyRings design makes it perfectly suitable for both duties of securing data
        /// on the wire as well as data at rest. In the former case, create a KeyRing, call
        /// KeyRing::Save and distribute it to the communicating peers. Have both peers call
        /// KeyRing::Load and use the master key to generate temporary session (active) keys.
        /// Once the session is over, destroy the KeyRing without calling KeyRing::Save.
        /// In the later case, create a KeyRing, use it to generate permanent encryption (active)
        /// keys, then call KeyRing::Save. Later call KeyRing::Load and use it to decrypt
        /// the data at rest.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyRing : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<KeyRing>.
            typedef util::ThreadSafeRefCounted::Ptr<KeyRing> Ptr;

            /// \brief
            /// KeyRing has it's own secure heap.
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (KeyRing, util::SpinLock)

        private:
            /// \brief
            /// key id.
            ID id;
            /// \brief
            /// Optional keyring name.
            std::string name;
            /// \brief
            /// Optional keyring description.
            std::string description;
            /// \brief
            /// Master key.
            Key::Ptr masterKey;
            /// \brief
            /// Convenient typedef for std::map<ID, Key::Ptr>.
            typedef std::map<ID, Key::Ptr> KeyMap;
            /// \brief
            /// Active key map.
            KeyMap activeKeyMap;
            /// \brief
            /// Where keys go to die.
            KeyMap retiredKeyMap;
            /// \brief
            /// Convenient typedef for std::map<ID, Ptr>.
            typedef std::map<ID, Ptr> KeyRingMap;
            /// \brief
            /// Subrings hanging off this keyring.
            KeyRingMap subrings;

        public:
            /// \brief
            /// ctor.
            /// \param[in] name_ Optional keyring name.
            /// \param[in] description_ Optional keyring description.
            /// \param[in] masterKey_ Master \see{Key}.
            KeyRing (
                const std::string &name_ = std::string (),
                const std::string &description_ = std::string (),
                Key::Ptr masterKey_ = Key::Ptr ()) :
                name (name_),
                description (description_),
                masterKey (masterKey_) {}
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
                Cipher::Ptr cipher,
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
                Cipher::Ptr cipher,
                const void *associatedData = 0,
                std::size_t associatedDataLength = 0);

            /// Return the key ring id.
            /// \return key ring id.
            inline const ID &GetId () const {
                return id;
            }

            /// Return the key ring name.
            /// \return key ring name.
            inline const std::string &GetName () const {
                return name;
            }

            /// Return the key ring description.
            /// \return key ring description.
            inline const std::string &GetDescription () const {
                return description;
            }

            /// \brief
            /// Return the master \see{Key}.
            /// \return The master \see{Key}.
            inline Key::Ptr GetMasterKey () const {
                return masterKey;
            }
            /// \brief
            /// Set the master key to the given key.
            /// \param[in] masterKey_ New master key to set.
            inline void SetMasterKey (Key::Ptr masterKey_) {
                masterKey = masterKey_;
            }

            /// \brief
            /// Retrieve the \see{Key} (master, active or retired) corresponding
            /// to the given id.
            /// \param[in] keyId Id of \see{Key} to retrieve.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return Master, active or retired \see{Key} corresponding to the
            /// given id. \see{Key::Ptr} () if not found.
            Key::Ptr GetKey (
                const ID &keyId,
                bool recursive = true) const;

            /// \brief
            /// Add a \see{Key} to the ring.
            /// \param[in] key \see{Key} to add.
            /// \return true = \see{Key} added. false = A \see{Key} with
            /// this id already exists in the ring.
            bool AddActiveKey (Key::Ptr key);
            /// \brief
            /// Given an active \see{Key} id, move the corresponding \see{Key}
            /// to the retired key map.
            /// \param[in] keyId Active \see{Key} id to retire.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = retired, false = not found.
            bool RetireActiveKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Given an active \see{Key} id, drop the corresponding \see{Key}
            /// from the key ring.
            /// \param[in] keyId Active \see{Key} id to drop from the key ring.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropActiveKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all active keys.
            /// \param[in] recursive true = descend down to sub rings.
            void DropActiveKeys (bool recursive = true);
            /// \brief
            /// Given a retired \see{Key} id, drop the corresponding \see{Key}
            /// from the key ring.
            /// \param[in] keyId Retired \see{Key} id to drop from the key ring.
            /// \param[in] recursive true = if not found locally, descend down to sub rings.
            /// \return true = dropped, false = not found.
            bool DropRetiredKey (
                const ID &keyId,
                bool recursive = true);
            /// \brief
            /// Drop all retired keys.
            /// \param[in] recursive descend down to sub rings.
            void DropRetiredKeys (bool recursive = true);
            /// \brief
            /// Drop all keys. Master key is not affected.
            /// \param[in] recursive descend down to sub rings.
            void DropAllKeys (bool recursive = true);

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
            /// Drop all keys and sub rings.
            void Clear ();

            /// \brief
            /// Return the serialized keyring size.
            /// \return Serialized keyring size.
            std::size_t Size () const;

            /// \brief
            /// Save the key ring to a serializer.
            /// \param[in] serializer Serializer to write the keyring to.
            void Serialize (util::Serializer &serializer) const;

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
            /// "MasterKey"
            static const char * const TAG_MASTER_KEY;
            /// \brief
            /// "ActiveKeys"
            static const char * const TAG_ACTIVE_KEYS;
            /// \brief
            /// "ActiveKey"
            static const char * const TAG_ACTIVE_KEY;
            /// \brief
            /// "RetiredKeys"
            static const char * const TAG_RETIRED_KEYS;
            /// \brief
            /// "RetiredKey"
            static const char * const TAG_RETIRED_KEY;
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
