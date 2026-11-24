#include "rtp.h"
#include "rtp_io.h"
#include "util.h"

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static volatile sig_atomic_t timeout_flag = 0;

void alarm_handler(int signo) {
    (void)signo;
    timeout_flag = 1;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        LOG_FATAL("Usage: ./receiver [listen port] [file path] [window size] "
                  "[mode]\n");
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) LOG_FATAL("socket() failed\n");

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons((uint16_t)atoi(argv[1]));
    local_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&local_addr,
             sizeof(local_addr)) < 0) {
        LOG_FATAL("bind() failed\n");
    }

    signal(SIGALRM, alarm_handler);
    alarm(5);

    int window_size = atoi(argv[3]);
    if (window_size <= 0) window_size = 1;
    int mode = atoi(argv[4]);

    struct sockaddr_in sender_addr;
    rtp_packet_t pkt;

    FILE *out = NULL;
    uint32_t rcv_base = 0;
    int have_base = 0;
    uint32_t expected_base = 0;
    int have_expected = 0;

    /* SR 缓存：窗口内每个槽位 */
    typedef struct {
        int received;
        uint16_t len;
        char payload[PAYLOAD_MAX];
    } slot_t;
    slot_t *slots = NULL;          /* 延迟分配，知道 rcv_base 后再按窗口大小分配 */

    while (!timeout_flag) {
        socklen_t addr_len = sizeof(sender_addr);
        ssize_t n = recvfrom(sockfd, &pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&sender_addr, &addr_len);

        if (timeout_flag) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_FATAL("recvfrom() failed\n");
        }
        if (!rtp_verify(&pkt, (size_t)n)) continue;

        if (pkt.rtp.flags & RTP_SYN) {
            expected_base = pkt.rtp.seq_num + 1;
            have_expected = 1;

            rtp_packet_t reply;
            if (rtp_prepare(&reply, pkt.rtp.seq_num + 1, 0,
                            RTP_SYN | RTP_ACK, NULL) == 0) {
                sendto(sockfd, &reply, sizeof(rtp_header_t), 0,
                       (struct sockaddr *)&sender_addr, addr_len);
            }
            alarm(5);

        } else if (pkt.rtp.flags == RTP_ACK && pkt.rtp.length == 0
                   && !have_base) {
            rcv_base = pkt.rtp.seq_num;
            have_base = 1;
            if (!out) {
                out = fopen(argv[2], "wb");
                if (!out) LOG_FATAL("open output failed\n");
            }
            alarm(5);

        } else if (pkt.rtp.length > 0 && pkt.rtp.flags == 0) {
            if (!have_base) {
                rcv_base = have_expected ? expected_base : pkt.rtp.seq_num;
                have_base = 1;
            }
            if (!out) {
                out = fopen(argv[2], "wb");
                if (!out) LOG_FATAL("open output failed\n");
            }

            if (mode == 0) {
                /* ---------------- GBN，保持原逻辑 ---------------- */
                if (pkt.rtp.seq_num == rcv_base) {
                    fwrite(pkt.payload, 1, pkt.rtp.length, out);
                    rcv_base++;
                }
                rtp_packet_t ack;
                rtp_prepare(&ack, rcv_base, 0, RTP_ACK, NULL);
                sendto(sockfd, &ack, sizeof(rtp_header_t), 0,
                       (struct sockaddr *)&sender_addr, addr_len);
            } else {
                /* ---------------- SR，mode = 1 ---------------- */
                if (!slots) {
                    slots = calloc((size_t)window_size, sizeof(slot_t));
                    if (!slots) LOG_FATAL("calloc slots failed\n");
                }

                uint32_t seq = pkt.rtp.seq_num;

                if (seq >= rcv_base
                    && seq < rcv_base + (uint32_t)window_size) {
                    /* 窗口内：缓存，并回 ACK(seq) —— 收到谁确认谁 */
		    int idx = (int)(seq % (uint32_t)window_size);
                    if (!slots[idx].received) {
                        slots[idx].received = 1;
                        slots[idx].len = pkt.rtp.length;
                        memcpy(slots[idx].payload, pkt.payload, pkt.rtp.length);
                    }

                    rtp_packet_t ack;
                    rtp_prepare(&ack, seq, 0, RTP_ACK, NULL);
                    sendto(sockfd, &ack, sizeof(rtp_header_t), 0,
                           (struct sockaddr *)&sender_addr, addr_len);

                    /* 当 rcv_base 本身到达后，连续交付已缓存的按序报文 */
                    while (1) {
			int b = (int)(rcv_base % (uint32_t)window_size);
                        if (!slots[b].received) break;
                        fwrite(slots[b].payload, 1, slots[b].len, out);
                        slots[b].received = 0;
                        rcv_base++;
                    }

                } else if (seq + (uint32_t)window_size <= rcv_base) {
                    /* 窗口之前的旧报文：直接回 ACK(seq)，不再缓存 */
                    rtp_packet_t ack;
                    rtp_prepare(&ack, seq, 0, RTP_ACK, NULL);
                    sendto(sockfd, &ack, sizeof(rtp_header_t), 0,
                           (struct sockaddr *)&sender_addr, addr_len);
                }
                /* 窗口之后的报文：忽略，不回 ACK */
            }
            alarm(5);

        } else if (pkt.rtp.flags & RTP_FIN) {
            rtp_packet_t reply;
            rtp_prepare(&reply, pkt.rtp.seq_num, 0,
                        RTP_FIN | RTP_ACK, NULL);
            sendto(sockfd, &reply, sizeof(rtp_header_t), 0,
                   (struct sockaddr *)&sender_addr, addr_len);
            break;
        }
    }

    if (out) fclose(out);
    free(slots);
    close(sockfd);
    LOG_DEBUG("Receiver: exiting...\n");
    return 0;
}

