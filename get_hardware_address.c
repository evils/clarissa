#include "get_hardware_address.h"

/* C89 standard headers */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/types.h>

/* Integer types */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
/* #include <pcap.h> */
#include <sys/ioctl.h>
/* #include <sys/bufmod.h> */
#include <search.h>


#define MAXLINE 255	/* Max line length for input files */
#define ETH_ALEN 6	/* Octets in one ethernet addr */


void err_sys(const char* fmt,...);
void err_msg(const char* fmt,...);
void warn_msg(const char* fmt,...);
void err_print(int errnoflag, const char* fmt, va_list ap);
void* Malloc(size_t size);
size_t strlcat(char* dst, const char* src, size_t siz);
size_t strlcpy(char* dst, const char* src, size_t siz);

void err_sys(const char* fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	err_print(1, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

void err_msg(const char* fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	err_print(0, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

void warn_msg(const char* fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	err_print(0, fmt, ap);
	va_end(ap);
}

void* Malloc(size_t size)
{
	void* result;

	result = malloc(size);

	if (result == NULL)
	{
		err_sys("malloc");
	}

	return result;
}

void err_print(int errnoflag, const char* fmt, va_list ap)
{
	int errno_save;
	size_t n;
	char buf[MAXLINE];

	errno_save=errno;

	vsnprintf(buf, MAXLINE, fmt, ap);
	n=strlen(buf);
	if (errnoflag)
	{
		snprintf(buf+n, MAXLINE-n, ": %s", strerror(errno_save));
	}
	strlcat(buf, "\n", sizeof(buf));

	fflush(stdout);		/* In case stdout and stderr are the same */
	fputs(buf, stderr);
	fflush(stderr);
}

size_t strlcat(char* dst, const char* src, size_t siz)
{
	char* d = dst;
	const char* s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
	{
		d++;
	}
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0) return(dlen + strlen(s));

	while (*s != '\0')
	{
		if (n != 1)
		{
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}

size_t strlcpy(char* dst, const char* src, size_t siz)
{
	char* d = dst;
	const char* s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0)
	{
		while (--n != 0)
		{
			if ((*d++ = *s++) == '\0') break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0)
	{
		if (siz != 0) *d = '\0';	/* NUL-terminate dst */
		while (*s++) ;
	}

	return(s - src - 1);	/* count does not include NUL */
}


/* most definitions from https://sourceforge.net/p/predef/wiki/OperatingSystems/ */
#if defined(__linux__) || defined(__linux) || defined(__gnu_linux__) || defined(linux) || defined(__ANDROID__) || defined(__GNU__) || defined(__gnu_hurd__)

#include <linux/if_packet.h>	/* struct sockaddr_ll sll */
#include <net/if.h>		/* struct ifreq, IFNAMSIZ */

/*
 *	Link layer handle structure for packet socket.
 *	This is typedef'ed as link_t.
 */
typedef struct link_handle
{
	int fd;		/* Socket file descriptor */
	struct ifreq ifr;
	struct sockaddr_ll sll;
} link_t;

/*
 *	link_open -- Open the specified link-level device
 *
 *	Inputs:
 *
 *	device		The name of the device to open
 *
 *	Returns:
 *
 *	A pointer to a link handle structure.
 */
static link_t* link_open(const char* device)
{
	link_t* handle;

	handle = Malloc(sizeof(*handle));
	memset(handle, '\0', sizeof(*handle));
	if ((handle->fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0)
	{
		warn_msg("ERROR: Cannot open raw packet socket");
		err_sys("socket");
	}
	strlcpy(handle->ifr.ifr_name, device, sizeof(handle->ifr.ifr_name));
	if ((ioctl(handle->fd, SIOCGIFINDEX, &(handle->ifr))) != 0)
	{
		err_sys("ioctl");
	}
	handle->sll.sll_family = PF_PACKET;
	handle->sll.sll_ifindex = handle->ifr.ifr_ifindex;
	handle->sll.sll_halen = ETH_ALEN;

	return handle;
}

/*
 *	link_close -- Close the link
 *
 *	Inputs:
 *
 *	handle		The handle for the link interface
 *
 *	Returns:
 *
 *	None
 */
static void link_close(link_t* handle)
{
	if (handle != NULL)
	{
		if (handle->fd != 0) close(handle->fd);

		free(handle);
	}
}

/*
 *	get_hardware_address	the Ethernet MAC address associated
 *				with the given device.
 *	Inputs:
 *
 *	if_name		The name of the network interface
 *	hw_address	(output) the Ethernet MAC address
 *
 *	Returns:
 *
 *	None
 */
void get_hardware_address
(const char* if_name, unsigned char hw_address[])
{
	link_t* handle;

	handle = link_open(if_name);
	if(!handle)
	{
		err_sys("link_open");
		return;
	}

	/* Obtain hardware address for specified interface */
	if ((ioctl(handle->fd, SIOCGIFHWADDR, &(handle->ifr))) != 0)
	{
		err_sys("ioctl");
	}

	memcpy(hw_address, handle->ifr.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

	link_close(handle);
}


#elif defined(__unix__) || defined(__unix) || defined(unix) || (defined(__APPLE__) && defined(__MACH__)) || defined(macintosh) || defined (Macintosh) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(DragonFly__) || defined(__bsdi__) || defined(_SYSTYPE_BSD) || defined(__FreeBSD_kernel__)

#include <net/if.h>
#include <net/route.h>
/* OpenBSD needs sys/param.h */
#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>

void get_hardware_address
(const char* if_name, unsigned char hw_address[])
{
	struct if_msghdr* ifm;
	struct sockaddr_dl* sdl=NULL;
	unsigned char* p;
	unsigned char* buf;
	size_t len;
	int mib[] = { CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };
	/*
	 *	Use sysctl to obtain interface list.
	 *	We first call sysctl with the 3rd arg set to NULL to obtain the
	 *	required length, then malloc the buffer and call sysctl again to get
	 *	the data.
	 */
	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
	{
		err_sys("sysctl");
	}

	buf = Malloc(len);

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
	{
		err_sys("sysctl");
	}
	/*
	 *	Go through all the interfaces in the list until we find the one that
	 *	corresponds to the device we are using.
	 */
	for (p = buf; p < buf + len; p += ifm->ifm_msglen)
	{
		ifm = (struct if_msghdr*)p;
		sdl = (struct sockaddr_dl*)(ifm + 1);

		if (ifm->ifm_type != RTM_IFINFO || (ifm->ifm_addrs & RTA_IFP) == 0)
			continue;

		if (sdl->sdl_family != AF_LINK || sdl->sdl_nlen == 0)
			continue;

		if ((memcmp(sdl->sdl_data, if_name, sdl->sdl_nlen)) == 0)
			break;
	}

	if (p >= buf + len)
	{
		err_msg("Could not get hardware address for interface %s", if_name);
	}

	memcpy(hw_address, sdl->sdl_data + sdl->sdl_nlen, ETH_ALEN);
	free(buf);
}


#elif defined(__sun) || defined(sun)

#include <sys/stat.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/dlpi.h>
#include <sys/dlpihdr.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>

/* Neal Nuckolls' sample code defines MAXDLBUF as 8192 longwords, but we use
 * unsigned char for our buffers and so must multiply by four */
#define MAXDLBUF 8192*4

/*
 *	Link layer handle structure for DLPI.
 *	This is typedef'ed as link_t.
 */
typedef struct link_handle
{
	int fd;
	int sap_first;
	struct ifreq ifr;
} link_t;

#if defined(DLIOCRAW) || defined(HAVE_SYS_DLPIHDR_H)
static int strioctl(int fd, int cmd, int len, char* dp)
{
	struct strioctl str;

	str.ic_cmd = cmd;
	str.ic_timout = INFTIM;
	str.ic_len = len;
	str.ic_dp = dp;

	if (ioctl(fd, I_STR, &str) < 0) return -1;

	return str.ic_len;
}
#endif

#ifdef HAVE_SYS_DLPIHDR_H
#define ND_BASE ('N' << 8)
#define ND_GET (ND_BASE + 0)
static int link_match_ppa(link_t* handle, const char* device)
{
	char* p;
	char dev[16];
	char buf[256];

	int len;
	int ppa;

	strlcpy(buf, "dl_ifnames", sizeof(buf));

	if ((len = strioctl(handle->fd, ND_GET, sizeof(buf), buf)) < 0)
	{
		return -1;
	}

	for (p = buf; p < buf + len; p += strlen(p) + 1)
	{
		ppa = -1;
		if (sscanf(p, "%s (PPA %d)\n", dev, &ppa) != 2)
			break;
		if (strcmp(dev, device) == 0)
			break;
	}
	return ppa;
}
#endif

static int dlpi_msg
(int fd, union DL_primitives* dlp, int rlen, int flags,
	unsigned ack, int alen, int size)
{
	struct strbuf ctl;

	ctl.maxlen = 0;
	ctl.len = rlen;
	ctl.buf = (caddr_t)dlp;

	if (putmsg(fd, &ctl, NULL, flags) < 0) return -1;

	ctl.maxlen = size;
	ctl.len = 0;
	flags = 0;

	if (getmsg(fd, &ctl, NULL, &flags) < 0) return -1;

	if (dlp->dl_primitive != ack || ctl.len < alen) return -1;

	return 0;
}

static void link_close(link_t* handle)
{
	if (handle != NULL)
	{
		if (handle->fd >= 0)
		{
			close(handle->fd);
		}
		free(handle);
	}
}

static link_t* link_open(const char* device)
{
	union DL_primitives* dlp;
	unsigned char buf[MAXDLBUF];
	char* p;
	char dev[16];
	link_t* handle;
	int ppa;

	handle = Malloc(sizeof(*handle));
	memset(handle, '\0', sizeof(*handle));

#ifdef HAVE_SYS_DLPIHDR_H
	if ((handle->fd = open("/dev/streams/dlb", O_RDWR)) < 0)
	{
		free(handle);
		return NULL;
	}

	if ((ppa = link_match_ppa(handle, device)) < 0)
	{
		link_close(handle);
		return NULL;
	}
#else
	handle->fd = -1;
	snprintf(dev, sizeof(dev), "/dev/%s", device);
	if ((p = strpbrk(dev, "0123456789")) == NULL)
	{
		link_close(handle);
		return NULL;
	}
	ppa = atoi(p);
	*p = '\0';

	if ((handle->fd = open(dev, O_RDWR)) < 0)
	{
		snprintf(dev, sizeof(dev), "/dev/%s", device);
		if ((handle->fd = open(dev, O_RDWR)) < 0)
		{
			link_close(handle);
			return NULL;
		}
	}
#endif
	memset(&(handle->ifr), 0, sizeof(struct ifreq));
	strlcpy(handle->ifr.ifr_name, device, sizeof(handle->ifr.ifr_name));
	dlp = (union DL_primitives*)buf;
	dlp->info_req.dl_primitive = DL_INFO_REQ;

	if (dlpi_msg(handle->fd, dlp, DL_INFO_REQ_SIZE, RS_HIPRI, DL_INFO_ACK,
		DL_INFO_ACK_SIZE, sizeof(buf)) < 0)
	{
		link_close(handle);
		return NULL;
	}

	handle->sap_first = (dlp->info_ack.dl_sap_length > 0);

	if (dlp->info_ack.dl_provider_style == DL_STYLE2)
	{
		dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
		dlp->attach_req.dl_ppa = ppa;

		if (dlpi_msg(handle->fd, dlp, DL_ATTACH_REQ_SIZE, 0, DL_OK_ACK,
			DL_OK_ACK_SIZE, sizeof(buf)) < 0)
		{
			link_close(handle);
			return NULL;
		}
	}
	memset(&dlp->bind_req, 0, DL_BIND_REQ_SIZE);
	dlp->bind_req.dl_primitive = DL_BIND_REQ;
#ifdef DL_HP_RAWDLS
	dlp->bind_req.dl_sap = 24;	/* from HP-UX DLPI programmers guide */
	dlp->bind_req.dl_service_mode = DL_HP_RAWDLS;
#else
	dlp->bind_req.dl_sap = DL_ETHER;
	dlp->bind_req.dl_service_mode = DL_CLDLS;
#endif
	if (dlpi_msg(handle->fd, dlp, DL_BIND_REQ_SIZE, 0, DL_BIND_ACK,
		DL_BIND_ACK_SIZE, sizeof(buf)) < 0)
	{
		link_close(handle);
		return NULL;
	}
#ifdef DLIOCRAW
	if (strioctl(handle->fd, DLIOCRAW, 0, NULL) < 0)
	{
		link_close(handle);
		return NULL;
	}
#endif
	return (handle);
}

void get_hardware_address
(const char* if_name, unsigned char hw_address[])
{
	union DL_primitives* dlp;
	unsigned char buf[MAXDLBUF];
	link_t* handle;

	handle = link_open(if_name);
	if (!handle)
	{
		err_msg("ERROR: cannot open interface %s with DLPI", if_name);
	}

	dlp = (union DL_primitives*) buf;
	dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
	dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;
	if (dlpi_msg(handle->fd, dlp, DL_PHYS_ADDR_REQ_SIZE, 0, DL_PHYS_ADDR_ACK,
		DL_PHYS_ADDR_ACK_SIZE, sizeof(buf)) < 0)
	{
		err_msg("dlpi_msg failed");
	}

	link_close(handle);
	memcpy(hw_address, buf + dlp->physaddr_ack.dl_addr_offset, ETH_ALEN);
}


#elif defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(TOS_WIN__) || defined(__WINDOWS__) || defined(OS_Windows)
/* TODO
 * placeholder
*/
#include <err.h>
void get_hardware_address
(const char* if_name, unsigned char hw_address[])
{
	errx(1, "Cannot get interface hardware address (MAC) on windows.");
}
#endif
