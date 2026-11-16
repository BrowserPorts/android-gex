/* sys/time.h for Windows programs (gexcc-win), as MinGW's: timeval and gettimeofday */
#pragma once
#include <time.h>
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _TIMEVAL_DEFINED
#define _TIMEVAL_DEFINED
struct timeval { long tv_sec; long tv_usec; };
#endif
#ifndef _TIMEZONE_DEFINED
#define _TIMEZONE_DEFINED
struct timezone { int tz_minuteswest; int tz_dsttime; };
#endif
int __cdecl gettimeofday(struct timeval *, void *);
#ifdef __cplusplus
}
#endif
