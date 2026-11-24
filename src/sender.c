#include "rtp.h"
#include "rtp_io.h"
#include "util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

/* 返回当前毫秒时间戳 */
static long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        LOG_FATAL("Usage: ./sender [receiver ip] [receiver port] [file path] "
                  "[window size] [mode]\n");
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) LOG_FATAL("socket() failed\n");

    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &receiver_addr.sin_addr) != 1) {
        LOG_FATAL("invalid receiver ip\n");
    }

    srand((unsigned)time(NULL));
    uint32_t init_seq = (uint32_t)rand() % ((1u << 30) - 200000u);

    /* 三次握手，与 GBN 相同 */
    int ok = 0;
    for (int i = 0; i < 50; i++) {
        if (send_rtp_and_wait_ack(sockfd, &receiver_addr,
                                  init_seq, 0, RTP_SYN, NULL,
                                  init_seq + 1, RTP_SYN | RTP_ACK) == 0) {
            ok = 1;
            break;
        }
    }
    if (!ok) LOG_FATAL("SYN handshake failed\n");

    rtp_packet_t ack3;
    rtp_prepare(&ack3, init_seq + 1, 0, RTP_ACK, NULL);
    sendto(sockfd, &ack3, sizeof(rtp_header_t), 0,
           (struct sockaddr *)&receiver_addr, sizeof(receiver_addr));

    /* 读文件 */
    FILE *fp = fopen(argv[3], "rb");
    if (!fp) LOG_FATAL("open file failed\n");
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *data = malloc((size_t)fsize);
    if (!data) LOG_FATAL("malloc failed\n");
    if (fread(data, 1, (size_t)fsize, fp) != (size_t)fsize) {
        LOG_FATAL("read file failed\n");
    }
    fclose(fp);

    int window_size = atoi(argv[4]);
    if (window_size <= 0) window_size = 1;
    int mode = atoi(argv[5]);

    int nchunks = (int)((fsize + PAYLOAD_MAX - 1) / PAYLOAD_MAX);
    uint32_t first_data_seq = init_seq + 1;
    uint32_t max_seq = first_data_seq + (uint32_t)nchunks;

    /* 每个序号在文件中的偏移和长度 */
    #define IDX(s) ((int)((s) - first_data_seq))
    #define LEN(s) ((IDX(s) == nchunks - 1) \
                ? (int)(fsize - (long)IDX(s) * PAYLOAD_MAX) \
                : PAYLOAD_MAX)

    if (mode == 0) {
        /* ---------------- GBN，保持原逻辑 ---------------- */
        uint32_t base_seq = first_data_seq;
        uint32_t next_seq = first_data_seq;

        while (base_seq < max_seq) {
            while (next_seq < max_seq &&
                   next_seq < base_seq + (uint32_t)window_size) {
                int idx = IDX(next_seq);
                int len = LEN(next_seq);
                rtp_packet_t p;
                rtp_prepare(&p, next_seq, (uint16_t)len, 0,
                            data + (long)idx * PAYLOAD_MAX);
                sendto(sockfd, &p, sizeof(rtp_header_t) + len, 0,
                       (struct sockaddr *)&receiver_addr,
                       sizeof(receiver_addr));
                next_seq++;
            }

            rtp_packet_t ack;
            ssize_t n = wait_for_packet(sockfd, &ack, &receiver_addr, 100);
            if (n > 0 && rtp_verify(&ack, (size_t)n)
                && (ack.rtp.flags & RTP_ACK)) {
                if (ack.rtp.seq_num > base_seq
                    && ack.rtp.seq_num <= next_seq) {
                    base_seq = ack.rtp.seq_num;
                }
            } else {
                for (uint32_t s = base_seq; s < next_seq; s++) {
                    int idx = IDX(s);
                    int len = LEN(s);
                    rtp_packet_t p;
                    rtp_prepare(&p, s, (uint16_t)len, 0,
                                data + (long)idx * PAYLOAD_MAX);
                    sendto(sockfd, &p, sizeof(rtp_header_t) + len, 0,
                           (struct sockaddr *)&receiver_addr,
                           sizeof(receiver_addr));
                }
            }
        }
    } else {
        /* ---------------- SR，mode = 1 ---------------- */
        uint32_t base_seq = first_data_seq;
        uint32_t next_seq = first_data_seq;

        /* 每个序号是否已被单独确认 */
        char *acked = calloc((size_t)nchunks, 1);
        /* 每个序号最后一次发送的时间戳（毫秒） */
        long long *sent_at = malloc((size_t)nchunks * sizeof(long long));
        if (!acked || !sent_at) LOG_FATAL("calloc/malloc failed\n");

        while (base_seq < max_seq) {
            /* 1. 发送窗口内尚未发送的报文 */
            while (next_seq < max_seq &&
                   next_seq < base_seq + (uint32_t)window_size) {
                int idx = IDX(next_seq);
                int len = LEN(next_seq);
                rtp_packet_t p;
                rtp_prepare(&p, next_seq, (uint16_t)len, 0,
                            data + (long)idx * PAYLOAD_MAX);
                sendto(sockfd, &p, sizeof(rtp_header_t) + len, 0,
                       (struct sockaddr *)&receiver_addr,
                       sizeof(receiver_addr));
                sent_at[idx] = now_ms();
                next_seq++;
            }

            /* 2. 计算最近的超时截止时间 */
            long long now = now_ms();
            long long next_deadline = now + 100;  /* 默认 100 ms 后检查 */
            for (uint32_t s = base_seq; s < next_seq; s++) {
                int idx = IDX(s);
                if (acked[idx]) continue;
                long long deadline = sent_at[idx] + 100;
                if (deadline < next_deadline) next_deadline = deadline;
            }
            int wait_ms = (int)(next_deadline - now);
            if (wait_ms < 0) wait_ms = 0;

            /* 3. 等待 ACK 或最近超时 */
            rtp_packet_t ack;
            ssize_t n = wait_for_packet(sockfd, &ack, &receiver_addr,
                                        wait_ms);
            if (n > 0 && rtp_verify(&ack, (size_t)n)
                && (ack.rtp.flags & RTP_ACK)) {
                /* SR：ack.seq_num 是"已成功收到的那个报文" */
                if (ack.rtp.seq_num >= base_seq
                    && ack.rtp.seq_num < next_seq) {
                    acked[IDX(ack.rtp.seq_num)] = 1;
                }

                /* 只有 base 本身被确认，窗口才前进到下一个未确认序号 */
                while (base_seq < max_seq && acked[IDX(base_seq)]) {
                    base_seq++;
                }
            } else {
                /* 4. 超时：只重传最近超时的那些单个报文 */
                now = now_ms();
                for (uint32_t s = base_seq; s < next_seq; s++) {
                    int idx = IDX(s);
                    if (acked[idx]) continue;
                    if (now - sent_at[idx] >= 100) {
                        int len = LEN(s);
                        rtp_packet_t p;
                        rtp_prepare(&p, s, (uint16_t)len, 0,
                                    data + (long)idx * PAYLOAD_MAX);
                        sendto(sockfd, &p, sizeof(rtp_header_t) + len, 0,
                               (struct sockaddr *)&receiver_addr,
                               sizeof(receiver_addr));
                        sent_at[idx] = now_ms();
                    }
                }
            }
        }

        free(acked);
        free(sent_at);
    }

    /* FIN，与 GBN 相同的循环 */
    uint32_t fin_seq = max_seq;
    int fin_ok = 0;
    int attempts = 0;
    while (attempts < 50 && !fin_ok) {
        rtp_packet_t fin;
        rtp_prepare(&fin, fin_seq, 0, RTP_FIN, NULL);
        sendto(sockfd, &fin, sizeof(rtp_header_t), 0,
               (struct sockaddr *)&receiver_addr, sizeof(receiver_addr));
        attempts++;

        while (1) {
            rtp_packet_t ack;
            ssize_t n = wait_for_packet(sockfd, &ack, &receiver_addr, 100);
            if (n <= 0) break;
            if (!rtp_verify(&ack, (size_t)n)) continue;
            if (ack.rtp.flags == (RTP_FIN | RTP_ACK)
                && ack.rtp.seq_num == fin_seq) {
                fin_ok = 1;
                break;
            }
        }
    }
    if (!fin_ok) LOG_FATAL("FIN handshake failed\n");

    free(data);
    close(sockfd);
    LOG_DEBUG("Sender: exiting...\n");
    return 0;
}

