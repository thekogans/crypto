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

#include "thekogans/crypto/FrameHeader.h"

namespace thekogans {
    namespace util {

        void ValueParser<crypto::FrameHeader>::Reset () {
            keyIdParser.Reset ();
            ciphertextLengthParser.Reset ();
            state = STATE_KEY_ID;
        }

        bool ValueParser<crypto::FrameHeader>::ParseValue (Serializer &serializer) {
            if (state == STATE_KEY_ID) {
                if (keyIdParser.ParseValue (serializer)) {
                    state = STATE_CIPHERTEXT_LENGTH;
                }
            }
            if (state == STATE_CIPHERTEXT_LENGTH) {
                if (ciphertextLengthParser.ParseValue (serializer)) {
                    Reset ();
                    return true;
                }
            }
            return false;
        }

    } // namespace util
} // namespace thekogans
