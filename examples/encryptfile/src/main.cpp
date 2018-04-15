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

#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/File.h"
#include "thekogans/util/Array.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/KeyRing.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/crypto/SymmetricKey.h"

using namespace thekogans;

namespace {
    std::string GetCipherSuites () {
        std::string cipherSuites_;
        const std::vector<crypto::CipherSuite> &cipherSuites =
            crypto::CipherSuite::GetCipherSuites ();
        if (!cipherSuites.empty ()) {
            cipherSuites_ = cipherSuites[0].ToString ();
            for (std::size_t i = 1, count = cipherSuites.size (); i < count; ++i) {
                cipherSuites_ += " | " + cipherSuites[i].ToString ();
            }
        }
        return cipherSuites_;
    }
}

int main (
        int argc,
        const char *argv[]) {
    struct Options : public util::CommandLineOptions {
        bool help;
        crypto::CipherSuite cipherSuite;
        std::string name;
        std::string description;
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
                case 'c': {
                    cipherSuite = crypto::CipherSuite (value);
                    break;
                }
                case 'n': {
                    name = value;
                    break;
                }
                case 'd': {
                    description = value;
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
    options.Parse (argc, argv, "hcndbp");
    if (options.help || options.password.empty () || options.path.empty ()) {
        std::cout << "usage: " << argv[0] << " [-h] [-c:'" << GetCipherSuites () << "'] "
            "[-n:'optional key ring name'] [-d:'optional key ring description'] "
            "[-b:'block size (in MB)'] -p:password path" << std::endl;
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
        crypto::KeyRing::Ptr keyRing;
        crypto::Cipher::Ptr cipher;
        if (options.cipherSuite != crypto::CipherSuite::Empty) {
            keyRing.Reset (
                new crypto::KeyRing (
                    options.cipherSuite,
                    options.name,
                    options.description));
        }
        else {
            cipher.Reset (
                new crypto::Cipher (
                    crypto::SymmetricKey::FromSecretAndSalt (
                        crypto::GetCipherKeyLength (),
                        options.password.c_str (),
                        options.password.size ())));
        }
        util::ui32 blockSize = 1024 * 1024 * options.blockSize;
        toFile << blockSize;
        util::Array<util::ui8> plaintext (blockSize);
        util::Array<util::ui8> ciphertext (crypto::Cipher::GetMaxBufferLength (blockSize));
        for (util::ui32 plaintextLength = fromFile.Read (plaintext.array, blockSize);
                plaintextLength != 0;
                plaintextLength = fromFile.Read (plaintext.array, blockSize)) {
            util::ui32 ciphertextLength;
            if (keyRing.Get () != 0) {
                crypto::SymmetricKey::Ptr key =
                    crypto::SymmetricKey::FromRandom (
                        crypto::GetCipherKeyLength (
                            options.cipherSuite.GetOpenSSLCipher ()));
                keyRing->AddCipherKey (key);
                cipher = keyRing->GetCipherSuite ().GetCipher (key);
                ciphertextLength =
                    (util::ui32)cipher->EncryptAndFrame (
                        plaintext.array, plaintextLength, 0, 0, ciphertext.array);
            }
            else {
                ciphertextLength =
                    (util::ui32)cipher->EncryptAndEnlengthen (
                        plaintext.array, plaintextLength, 0, 0, ciphertext.array);
            }
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
        if (keyRing.Get () != 0) {
            std::cout << "Saving key ring...";
            cipher.Reset (
                new crypto::Cipher (
                    crypto::SymmetricKey::FromSecretAndSalt (
                        crypto::GetCipherKeyLength (
                            options.cipherSuite.GetOpenSSLCipher ()),
                        options.password.c_str (),
                        options.password.size ())));
            keyRing->Save (options.path + ".tkr", cipher.Get ());
            std::cout << "Done" << std::endl;
        }
    }
    THEKOGANS_UTIL_CATCH_AND_LOG
    THEKOGANS_UTIL_LOG_FLUSH
    return 0;
}
