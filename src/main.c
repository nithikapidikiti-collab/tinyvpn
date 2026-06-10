#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "tunnel.h"
#include "crypto.h"

static volatile int running = 1;
static void handle_sig(int s) { (void)s; running = 0; }
static uint64_t bytes_in = 0, bytes_out = 0, pkt_in = 0, pkt_out = 0;

static void print_stats(void) {
    printf("\n[stats] pkts_in=%llu bytes_in=%llu | pkts_out=%llu bytes_out=%llu\n",
           (unsigned long long)pkt_in,  (unsigned long long)bytes_in,
           (unsigned long long)pkt_out, (unsigned long long)bytes_out);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <server|client> <bind_port> <peer_ip> <peer_port>\n", argv[0]);
        fprintf(stderr, "  Set TINYVPN_KEY to 64 hex chars\n");
        return 1;
    }
    const char *mode      = argv[1];
    int         bind_port = atoi(argv[2]);
    const char *peer_ip   = argv[3];
    int         peer_port = atoi(argv[4]);

    const char *key_hex = getenv("TINYVPN_KEY");
    if (!key_hex || strlen(key_hex) != 64) {
        fprintf(stderr, "[!] Set TINYVPN_KEY to 64 hex chars (32 bytes)\n"); return 1;
    }
    uint8_t key[KEY_LEN];
    for (int i = 0; i < KEY_LEN; i++) sscanf(key_hex + 2*i, "%2hhx", &key[i]);

    printf("[tinyvpn] mode=%s bind=%d peer=%s:%d\n", mode, bind_port, peer_ip, peer_port);

    int tun_fd = tun_open("utun");
    if (tun_fd < 0) { fprintf(stderr, "[!] Failed to open TUN\n"); return 1; }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET; local.sin_port = htons(bind_port); local.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_fd, (struct sockaddr *)&local, sizeof(local)) < 0) { perror("bind"); return 1; }

    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET; peer.sin_port = htons(peer_port);
    inet_pton(AF_INET, peer_ip, &peer.sin_addr);

    signal(SIGINT, handle_sig); signal(SIGTERM, handle_sig);
    printf("[tinyvpn] tunnel up. Ctrl+C to stop.\n");
    printf("[tinyvpn] configure with: sudo ifconfig utun<N> 10.0.0.1 10.0.0.2\n\n");

    uint8_t ip_buf[MTU];
    vpn_packet_t pkt;

    while (running) {
        fd_set fds; FD_ZERO(&fds); FD_SET(tun_fd, &fds); FD_SET(udp_fd, &fds);
        int maxfd = (tun_fd > udp_fd ? tun_fd : udp_fd) + 1;
        struct timeval tv = {1, 0};
        if (select(maxfd, &fds, NULL, NULL, &tv) <= 0) continue;

        if (FD_ISSET(tun_fd, &fds)) {
            int n = tun_read(tun_fd, ip_buf, sizeof(ip_buf));
            if (n <= 0) continue;
            crypto_random_bytes(pkt.iv, IV_LEN);
            pkt.magic = htonl(PACKET_MAGIC);
            int ct_len = crypto_encrypt(ip_buf, n, key, pkt.iv, pkt.data, pkt.tag);
            if (ct_len < 0) { fprintf(stderr, "[!] encrypt failed\n"); continue; }
            pkt.length = htons((uint16_t)ct_len);
            size_t send_len = sizeof(uint32_t) + IV_LEN + TAG_LEN + sizeof(uint16_t) + ct_len;
            sendto(udp_fd, &pkt, send_len, 0, (struct sockaddr *)&peer, sizeof(peer));
            bytes_out += n; pkt_out++;
        }

        if (FD_ISSET(udp_fd, &fds)) {
            struct sockaddr_in src; socklen_t src_len = sizeof(src);
            ssize_t n = recvfrom(udp_fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&src, &src_len);
            if (n <= 0) continue;
            if (ntohl(pkt.magic) != PACKET_MAGIC) { fprintf(stderr, "[!] bad magic\n"); continue; }
            uint16_t ct_len = ntohs(pkt.length);
            int pt_len = crypto_decrypt(pkt.data, ct_len, key, pkt.iv, pkt.tag, ip_buf);
            if (pt_len < 0) { fprintf(stderr, "[!] decrypt failed\n"); continue; }
            tun_write(tun_fd, ip_buf, pt_len);
            bytes_in += pt_len; pkt_in++;
        }
    }
    print_stats(); tun_close(tun_fd); close(udp_fd);
    return 0;
}
