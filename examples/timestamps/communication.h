#ifndef MESSAGE_H
#define MESSAGE_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define HI_TYPE 14
#define TIME_TYPE 16

enum SockTypes {
	SOCK_TYPE_INET_DGRAM,
	SOCK_TYPE_INET_RAW,
	SOCK_TYPE_INET_RAW_IP_HDRINCL,
	SOCK_TYPE_PACKET_DGRAM,
	SOCK_TYPE_PACKET_RAW,
	SOCK_TYPE_XDP,
	SOCK_TYPE_INVALID
};

struct Headers {
	struct ethhdr eth;
	struct iphdr ip;
	struct udphdr udp;
} __attribute__((packed));

struct Timestamp {
	uint64_t seconds;
	uint32_t nanoseconds;
} __attribute__((packed));

struct RequestPayload {
	uint8_t type;
	uint32_t seq;
} __attribute__((packed));

struct RequestMessage {
	struct Headers hdr;
	struct RequestPayload payload;
} __attribute__((packed));

struct ResponsePayload {
	uint8_t type;
	uint32_t seq;
	struct Timestamp user;
	struct Timestamp sw;
	struct Timestamp hw;
} __attribute__((packed));

struct ResponseMessage {
	struct Headers hdr;
	struct ResponsePayload payload;
} __attribute__((packed));

struct Addresses {
	struct sockaddr_in in;
	struct sockaddr_ll ll;
};

enum SockTypes parse_sock_type(const char *str);
int setup_socket(const char *interface, int priority, int port,
		 struct Addresses *src_addr, enum SockTypes sock_type);
int prepare_headers(const struct Addresses *src_addr,
		    const struct Addresses *dest_addr, struct Headers *hdr,
		    size_t payload_size, enum SockTypes sock_type);
int send_message(int sockfd, const struct Addresses *dest_addr, uint8_t *msg,
		 size_t total_msg_size, enum SockTypes sock_type);
int receive_offset(enum SockTypes sock_type);
int receive_message(int sockfd, uint8_t *data, size_t total_data_size,
		    enum SockTypes sock_type);

int receive_timestamped_message(int sockfd, uint8_t *message, size_t max_size,
				int flags, struct timespec *ts_sw,
				struct timespec *ts_hw,
				struct timespec *ts_user, int *tstype,
				int *tskey, struct Addresses *addresses,
				enum SockTypes sock_type);

#endif
