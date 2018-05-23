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

#if !defined (__thekogans_crypto_OpenSSLException_h)
#define __thekogans_crypto_OpenSSLException_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \brief
        /// These extensions to \see{thekogans::util::Exception} allow
        /// OpenSSL errors to be treated uniformly just like all the rest.

        /// \brief
        /// Create an \see{thekogans::util::Exception} and traceback using
        /// OpenSSL's error stack.
        /// \param[in] file Translation unit.
        /// \param[in] function Function in the translation unit.
        /// \param[in] line Translation unit line number.
        /// \param[in] buildTime Translation unit build time.
        /// \param[in] message Extra message to add to the exception report.
        /// \return An \see{thekogans::util::Exception} and traceback.
        _LIB_THEKOGANS_CRYPTO_DECL util::Exception _LIB_THEKOGANS_CRYPTO_API
            CreateOpenSSLException (
                const char *file,
                const char *function,
                util::ui32 line,
                const char *buildTime,
                const char *message = "");

        /// \def THEKOGANS_CRYPTO_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Build an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_OPENSSL_EXCEPTION_EX(\
                file, function, line, buildTime)\
            thekogans::crypto::CreateOpenSSLException (\
                file, function, line, buildTime)
        /// \def THEKOGANS_CRYPTO_OPENSSL_EXCEPTION
        /// Build an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_OPENSSL_EXCEPTION\
            THEKOGANS_CRYPTO_OPENSSL_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__)

        /// \def THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION_EX(\
                file, function, line, buildTime)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw THEKOGANS_CRYPTO_OPENSSL_EXCEPTION_EX (\
                file, function, line, buildTime)
        /// \def THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION\
            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__)

        /// \def THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION_EX(
        ///          file, function, line, buildTime)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_THROW_OPENSSL_AND_MESSAGE_EXCEPTION_EX(\
                file, function, line, buildTime, format, ...)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw thekogans::crypto::CreateOpenSSLException (\
                file, function, line, buildTime,\
                thekogans::util::FormatString (format, __VA_ARGS__).c_str ())
        /// \def THEKOGANS_CRYPTO_THROW_OPENSSL_AND_MESSAGE_EXCEPTION(format, ...)
        /// Throw an Exception from OpenSSL error stack.
        #define THEKOGANS_CRYPTO_THROW_OPENSSL_AND_MESSAGE_EXCEPTION(\
                format, ...)\
            THEKOGANS_CRYPTO_THROW_OPENSSL_AND_MESSAGE_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__,\
                format, __VA_ARGS__)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLException_h)
