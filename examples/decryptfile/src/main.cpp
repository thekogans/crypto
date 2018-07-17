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

#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/Path.h"
#include "thekogans/util/File.h"
#include "thekogans/util/Array.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/KeyRing.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/crypto/SymmetricKey.h"

using namespace thekogans;

int main (
        int argc,
        const char *argv[]) {
    struct Options : public util::CommandLineOptions {
        bool help;
        std::string password;
        std::string path;

        Options () :
            help (false) {}

        virtual void DoOption (
                char option,
                const std::string &value) {
            switch (option) {
                case 'h': {
                    help = true;
                    break;
                }
                case 'p': {
                    password = value;
                    break;
                }
            }
        }
        virtual void DoPath (const std::string &value) {
            path = value;
        }
    } options;
    options.Parse (argc, argv, "hp");
    if (options.help || options.password.empty () || options.path.empty ()) {
        std::cout << "usage: " << argv[0] << " [-h] -p:password path" << std::endl;
        return 1;
    }
    THEKOGANS_UTIL_LOG_INIT (
        util::LoggerMgr::Debug,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (util::Logger::Ptr (new util::ConsoleLogger));
    THEKOGANS_UTIL_IMPLEMENT_LOG_FLUSHER;
    THEKOGANS_UTIL_TRY {
        crypto::OpenSSLInit openSSLInit;
        std::cout << "Decrypting '" << options.path + ".enc" << "'";
        util::ReadOnlyFile fromFile (util::NetworkEndian, options.path + ".enc");
        util::SimpleFile toFile (
            util::NetworkEndian,
            options.path,
            util::SimpleFile::ReadWrite |
            util::SimpleFile::Create |
            util::SimpleFile::Truncate);
        crypto::Cipher::Ptr cipher (
            new crypto::Cipher (
                crypto::SymmetricKey::FromSecretAndSalt (
                    options.password.c_str (),
                    options.password.size ())));
        crypto::KeyRing::Ptr keyRing;
        if (util::Path (options.path + ".tkr").Exists ()) {
            keyRing = crypto::KeyRing::Load (options.path + ".tkr", cipher.Get ());
        }
        util::ui32 blockSize;
        fromFile >> blockSize;
        util::Array<util::ui8> ciphertext (crypto::Cipher::GetMaxBufferLength (blockSize));
        util::Array<util::ui8> plaintext (blockSize);
        for (util::ui64 fromSize = fromFile.GetDataAvailableForReading (); fromSize != 0;) {
            util::ui32 ciphertextLength;
            if (keyRing.Get () != 0) {
                crypto::FrameHeader frameHeader;
                fromFile >> frameHeader;
                fromSize -= crypto::FrameHeader::SIZE;
                crypto::SymmetricKey::Ptr key = keyRing->GetCipherKey (frameHeader.keyId);
                if (key.Get () != 0) {
                    cipher = keyRing->GetCipherSuite ().GetCipher (key);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get key %s",
                        frameHeader.keyId.ToString ().c_str ());
                }
                ciphertextLength = frameHeader.ciphertextLength;
            }
            else {
                fromFile >> ciphertextLength;
                fromSize -= util::UI32_SIZE;
            }
            if (fromFile.Read (ciphertext.array, ciphertextLength) == ciphertextLength) {
                util::ui32 plaintextLength =
                    (util::ui32)cipher->Decrypt (ciphertext.array, ciphertextLength, 0, 0, plaintext.array);
                if (toFile.Write (plaintext.array, plaintextLength) == plaintextLength) {
                    std::cout << ".";
                    std::cout.flush ();
                    fromSize -= ciphertextLength;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to write %u bytes to %s",
                        plaintextLength,
                        toFile.GetPath ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to read %u bytes from %s",
                    ciphertextLength,
                    fromFile.GetPath ().c_str ());
            }
        }
        std::cout << "Done" << std::endl;
    }
    THEKOGANS_UTIL_CATCH_AND_LOG
    return 0;
}
