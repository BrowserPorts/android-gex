/* comutil.h (gexcc-win's compatibility headers): the string conversions of the
 * COM support library, declared as MinGW declares them */
#pragma once
#include <oleauto.h>
namespace _com_util {
BSTR __stdcall ConvertStringToBSTR(const char *);
char *__stdcall ConvertBSTRToString(BSTR);
}
