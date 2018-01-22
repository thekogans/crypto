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

#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/File.h"
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
        util::ui32 blockSize;
        std::string password;
        std::string path;

        Options () :
            help (false),
            blockSize (2) {}

        virtual void DoOption (
                char option,
                const std::string &value) {
            switch (option) {
                case 'h': {
                    help = true;
                    break;
                }
                case 'b': {
                    blockSize = util::stringToui32 (value.c_str ());
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
    options.Parse (argc, argv, "hbp");
    if (options.help || options.password.empty () || options.path.empty ()) {
        std::cout << "usage: " << argv[0] <<
            " [-h] [-b:'block size (in MB)'] -p:password path" << std::endl;
        return 1;
    }
    THEKOGANS_UTIL_LOG_INIT (
        util::LoggerMgr::Debug,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (util::Logger::Ptr (new util::ConsoleLogger));
    THEKOGANS_UTIL_TRY {
        crypto::OpenSSLInit openSSLInit;
        std::cout << "Encrypting '" << options.path << "'";
        util::ReadOnlyFile fromFile (util::NetworkEndian, options.path);
        util::SimpleFile toFile (
            util::NetworkEndian,
            options.path + ".enc",
            util::SimpleFile::ReadWrite |
            util::SimpleFile::Create |
            util::SimpleFile::Truncate);
        crypto::Cipher cipher (
            crypto::SymmetricKey::FromSecretAndSalt (
                crypto::Cipher::GetKeyLength (),
                options.password.c_str (),
                options.password.size ()));
        util::ui32 blockSize = 1024 * 1024 * options.blockSize;
        toFile << blockSize;
        util::Array<util::ui8> plaintext (blockSize);
        util::Array<util::ui8> ciphertext (crypto::Cipher::GetMaxBufferLength (blockSize));
        for (util::ui32 plaintextLength = fromFile.Read (plaintext.array, blockSize);
                plaintextLength != 0;
                plaintextLength = fromFile.Read (plaintext.array, blockSize)) {
            util::ui32 ciphertextLength =
                (util::ui32)cipher.Encrypt (plaintext.array, plaintextLength, 0, 0, ciphertext.array);
            toFile << ciphertextLength;
            if (toFile.Write (ciphertext.array, ciphertextLength) == ciphertextLength) {
                std::cout << ".";
                std::cout.flush ();
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to write %u bytes to %s",
                    ciphertextLength,
                    toFile.GetPath ().c_str ());
            }
        }
        std::cout << "Done" << std::endl;
    }
    THEKOGANS_UTIL_CATCH_AND_LOG
    THEKOGANS_UTIL_LOG_FLUSH
    return 0;
}
