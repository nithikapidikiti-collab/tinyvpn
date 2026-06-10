#include "tunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <netinet/ip.h>

int tun_open(const char *dev_name) {
    (void)dev_name;
    struct sockaddr_ctl addr;
    struct ctl_info info;
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) { perror("socket(PF_SYSTEM)"); return -1; }
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) { perror("ioctl(CTLIOCGINFO)"); close(fd); return -1; }
    memset(&addr, 0, sizeof(addr));
    addr.sc_len     = sizeof(addr);
    addr.sc_family  = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id      = info.ctl_id;
    addr.sc_unit    = 0;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("connect(utun)"); close(fd); return -1; }
    char ifname[20];
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == 0)
        printf("[tun] opened interface: %s\n", ifname);
    return fd;
}

void tun_close(int fd) { close(fd); }

int tun_read(int fd, uint8_t *buf, size_t len) {
    uint8_t tmp[MTU + 4];
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n <= 4) return -1;
    n -= 4;
    if ((size_t)n > len) n = len;
    memcpy(buf, tmp + 4, n);
    return (int)n;
}

int tun_write(int fd, const uint8_t *buf, size_t len) {
    uint8_t tmp[MTU + 4];
    tmp[0] = 0; tmp[1] = 0; tmp[2] = 0; tmp[3] = AF_INET;
    if (len > MTU) len = MTU;
    memcpy(tmp + 4, buf, len);
    ssize_t n = write(fd, tmp, len + 4);
    return (n > 4) ? (int)(n - 4) : -1;
}
