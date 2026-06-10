#ifndef TUNNEL_H
#define TUNNEL_H

#include <stdint.h>
#include <stddef.h>

#define MTU          1500
#define PACKET_MAGIC 0x56504E00

typedef struct {
    uint32_t magic;
    uint8_t  iv[12];
    uint8_t  tag[16];
    uint16_t length;
    uint8_t  data[MTU + 16];
} __attribute__((packed)) vpn_packet_t;

int  tun_open(const char *dev_name);
void tun_close(int fd);
int  tun_read(int fd, uint8_t *buf, size_t len);
int  tun_write(int fd, const uint8_t *buf, size_t len);

#endif
