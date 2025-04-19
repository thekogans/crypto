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

#if !defined (__thekogans_crypto_Argon2Exception_h)
#define __thekogans_crypto_Argon2Exception_h

#if defined (THEKOGANS_CRYPTO_HAVE_ARGON2)

#include <argon2.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \brief
        /// These extensions to \see{thekogans::util::Exception} allow
        /// Argon2 errors to be treated uniformly just like all the rest.

        /// \def THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION_EX(
        ///          file, function, line, buildTime, errorCode)
        /// Build an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION_EX(\
                file, function, line, buildTime, errorCode)\
            thekogans::util::Exception (file, function, line, buildTime,\
                errorCode, argon2_error_message (errorCode))
        /// \def THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION(errorCode)
        /// Build an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION(errorCode)\
            THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__, errorCode)

        /// \def THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION_EX(
        ///          file, function, line, buildTime, errorCode)
        /// Throw an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION_EX(\
                file, function, line, buildTime, errorCode)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw THEKOGANS_CRYPTO_ARGON2_ERROR_CODE_EXCEPTION_EX (\
                file, function, line, buildTime, errorCode)
        /// \def THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION(errorCode)
        /// Throw an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION(errorCode)\
            THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__, errorCode)

        /// \def THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_EXCEPTION_EX(
        ///          file, function, line, buildTime, errorCode, format, ...)
        /// Throw an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_AND_MESSAGE_EXCEPTION_EX(\
                file, function, line, buildTime, errorCode, format, ...)\
            THEKOGANS_UTIL_DEBUG_BREAK\
            throw thekogans::util::Exception (file, function, line, buildTime,\
                errorCode, argon2_error_message (errorCode))
        /// \def THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_AND_MESSAGE_EXCEPTION(
        ///          errorCode, format, ...)
        /// Throw an Exception from Argon2 error code.
        #define THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_AND_MESSAGE_EXCEPTION(\
                errorCode, format, ...)\
            THEKOGANS_CRYPTO_THROW_ARGON2_ERROR_CODE_AND_MESSAGE_EXCEPTION_EX (\
                __FILE__, __FUNCTION__, __LINE__, __DATE__ " " __TIME__,\
                errorCode, format, ##__VA_ARGS__)

    } // namespace crypto
} // namespace thekogans

#endif // defined (THEKOGANS_CRYPTO_HAVE_ARGON2)

#endif // !defined (__thekogans_crypto_Argon2Exception_h)
