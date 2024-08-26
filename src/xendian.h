#ifndef TOTP_XENDIAN_H
#define TOTP_XENDIAN_H

/* This header grabs the htobe64() and co. functions in a more
   cross-platform manner.  In general you will find these functions in
   <sys/endian.h>, however Linux and OpenBSD include them in <endian.h>.
   To make things even better this header doesn’t exist on MacOS so we
   need to define wrapper macros for the htonXX() functions from
   <arpa/inet.h>. */

#if defined(__OpenBSD__) || defined(__linux__)
#	include <endian.h>
#elif defined(__APPLE__)
#	include <arpa/inet.h>
#	define htobe32(x) htonl(x)
#	define htobe64(x) htonll(x)
#else
#	include <sys/endian.h>
#endif

#endif /* !TOTP_XENDIAN_H */
