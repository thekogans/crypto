// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_util.
//
// libthekogans_util is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_util is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_util. If not, see <http://www.gnu.org/licenses/>.

#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/File.h"
#include "thekogans/util/Directory.h"
#include "thekogans/util/Array.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/Cipher.h"

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
    options.Parse (argc, argv, "hcwp");
    if (options.help || options.password.empty () || options.path.empty ()) {
        std::cout << "usage: " << argv[0] << " [-h] -p:password path" << std::endl;
        return 1;
    }
    THEKOGANS_UTIL_LOG_INIT (
        util::LoggerMgr::Debug,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (util::Logger::Ptr (new util::ConsoleLogger));
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
        crypto::Cipher cipher (
            crypto::SymmetricKey::FromSecretAndSalt (
                crypto::Cipher::GetKeyLength (),
                options.password.c_str (),
                options.password.size ()));
        util::ui32 blockSize;
        fromFile >> blockSize;
        util::Array<util::ui8> ciphertext (crypto::Cipher::GetMaxBufferLength (blockSize));
        util::Array<util::ui8> plaintext (blockSize);
        for (util::ui64 fromSize = fromFile.GetDataAvailableForReading (); fromSize != 0;) {
            util::ui32 ciphertextLength;
            fromFile >> ciphertextLength;
            if (fromFile.Read (ciphertext.array, ciphertextLength) == ciphertextLength) {
                util::ui32 plaintextLength =
                    (util::ui32)cipher.Decrypt (ciphertext.array, ciphertextLength, 0, 0, plaintext.array);
                if (toFile.Write (plaintext.array, plaintextLength) == plaintextLength) {
                    std::cout << ".";
                    std::cout.flush ();
                    fromSize -= util::UI32_SIZE + ciphertextLength;
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
    THEKOGANS_UTIL_LOG_FLUSH
    return 0;
}
