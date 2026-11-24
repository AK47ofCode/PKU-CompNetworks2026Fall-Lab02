#include "rtp_io.h"
#include "util.h"

#include <string.h>
#include <sys/select.h>

int rtp_prepare(rtp_packet_t *pkt, uint32_t seq, uint16_t len,
                uint8_t flags, const char *payload) {
    if (len > PAYLOAD_MAX) return -1;
    if (len > 0 && payload == NULL) return -1;

    memset(pkt, 0, sizeof(*pkt));
    pkt->rtp.seq_num = seq;
    pkt->rtp.length  = len;
    pkt->rtp.flags   = flags;

    if (len > 0) {
        memcpy(pkt->payload, payload, len);
    }

    pkt->rtp.checksum = 0;
    pkt->rtp.checksum = compute_checksum(
        pkt, sizeof(rtp_header_t) + len
    );
    return 0;
}

int rtp_verify(rtp_packet_t *pkt, size_t recv_len) {
    if (recv_len < sizeof(rtp_header_t)) return 0;
    if (recv_len > sizeof(rtp_packet_t)) return 0;
    if (pkt->rtp.length > PAYLOAD_MAX) return 0;
    if (recv_len != sizeof(rtp_header_t) + pkt->rtp.length) return 0;

    uint32_t saved = pkt->rtp.checksum;
    pkt->rtp.checksum = 0;
    uint32_t computed = compute_checksum(pkt, recv_len);
    pkt->rtp.checksum = saved;

    return computed == saved;
}

ssize_t wait_for_packet(int sockfd, rtp_packet_t *pkt,
                        struct sockaddr_in *peer, int timeout_ms) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);
    if (ret == 0) return 0;   // 超时
    if (ret < 0) return -1;   // select 错误

    socklen_t addr_len = sizeof(*peer);
    return recvfrom(sockfd, pkt, sizeof(*pkt), 0,
                    (struct sockaddr *)peer, &addr_len);
}

int send_rtp_and_wait_ack(int sockfd, struct sockaddr_in *peer,
                          uint32_t seq, uint16_t len,
                          uint8_t flags, const char *payload,
                          uint32_t expected_ack_seq,
                          uint8_t expected_ack_flags) {
    rtp_packet_t pkt;
    if (rtp_prepare(&pkt, seq, len, flags, payload) != 0) return -1;

    sendto(sockfd, &pkt, sizeof(rtp_header_t) + len, 0,
           (struct sockaddr *)peer, sizeof(*peer));

    rtp_packet_t ack;
    ssize_t n = wait_for_packet(sockfd, &ack, peer, 100);
    if (n <= 0) return -1;
    if (!rtp_verify(&ack, (size_t)n)) return -1;

    if (ack.rtp.seq_num == expected_ack_seq &&
        ack.rtp.flags == expected_ack_flags) {
        return 0;
    }
    return -1;
}

