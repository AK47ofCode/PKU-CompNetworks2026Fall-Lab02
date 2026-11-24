#ifndef RTP_IO_H
#define RTP_IO_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "rtp.h"

int rtp_prepare(rtp_packet_t *pkt, uint32_t seq, uint16_t len,
                uint8_t flags, const char *payload);

int rtp_verify(rtp_packet_t *pkt, size_t recv_len);

ssize_t wait_for_packet(int sockfd, rtp_packet_t *pkt,
                        struct sockaddr_in *peer, int timeout_ms);

int send_rtp_and_wait_ack(int sockfd, struct sockaddr_in *peer,
                          uint32_t seq, uint16_t len,
                          uint8_t flags, const char *payload,
                          uint32_t expected_ack_seq,
                          uint8_t expected_ack_flags);

#endif
