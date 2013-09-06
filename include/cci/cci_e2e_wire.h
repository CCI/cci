/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_E2E_WIRE_H
#define CCI_E2E_WIRE_H

#include <string.h>
#include <arpa/inet.h>

#define U32_HI 0
#define U32_LO 1

static inline uint64_t
cci_e2e_htonll(uint64_t in)
{
	union {
		uint64_t u64;
		uint32_t u32[2];
	} out;

	out.u32[U32_HI] = htonl((uint32_t)(in >> 32));
	out.u32[U32_LO] = htonl((uint32_t)(in & 0xFFFFFFFF));

	return out.u64;
}

static inline uint64_t
cci_e2e_ntohll(uint64_t in)
{
	union {
		uint64_t u64;
		uint32_t u32[2];
	} out;

	out.u32[U32_HI] = ntohl((uint32_t)(in >> 32));
	out.u32[U32_LO] = ntohl((uint32_t)(in & 0xFFFFFFFF));

	return out.u64;
}

/* We can only use the lower 7 bits of the type. Router's set the 8th bit
 * for internal, router-to-router messages. */
typedef enum cci_e2e_msg_type {
	CCI_E2E_MSG_INVALID = 0,		/* Never used */
	CCI_E2E_MSG_CONN_REQUEST,
	CCI_E2E_MSG_CONN_REPLY,
	CCI_E2E_MSG_CONN_ACK,
	CCI_E2E_MSG_BYE,
	CCI_E2E_MSG_SEND,
	CCI_E2E_MSG_SEND_ACK,
	CCI_E2E_MSG_SEND_ACK_MANY,
	CCI_E2E_MSG_SEND_SACK,
	CCI_E2E_MSG_SEND_NACK,
	CCI_E2E_MSG_RMA_WRITE_REQ,
	CCI_E2E_MSG_RMA_WRITE_ACK,
	CCI_E2E_MSG_RMA_READ_REQ,
	CCI_E2E_MSG_RMA_READ_ACK,
	CCI_E2E_MSG_MAX = ((1 << 7) - 1)	/* We can never exceed this */
} cci_e2e_msg_type_t;

static inline const char *
cci_e2e_msg_type_str(cci_e2e_msg_type_t type)
{
	switch (type) {
	case CCI_E2E_MSG_INVALID:
		return "invalid";
	case CCI_E2E_MSG_CONN_REQUEST:
		return "E2E connect request";
	case CCI_E2E_MSG_CONN_REPLY:
		return "E2E connect reply";
	case CCI_E2E_MSG_CONN_ACK:
		return "E2E connect ack";
	case CCI_E2E_MSG_BYE:
		return "E2E bye";
	case CCI_E2E_MSG_SEND:
		return "E2E send";
	case CCI_E2E_MSG_SEND_ACK:
		return "E2E send ack";
	case CCI_E2E_MSG_SEND_ACK_MANY:
		return "E2E send ack many";
	case CCI_E2E_MSG_SEND_SACK:
		return "E2E send sack";
	case CCI_E2E_MSG_SEND_NACK:
		return "E2E send nack";
	case CCI_E2E_MSG_RMA_WRITE_REQ:
		return "E2E RMA write request";
	case CCI_E2E_MSG_RMA_WRITE_ACK:
		return "E2E RMA write ack";
	case CCI_E2E_MSG_RMA_READ_REQ:
		return "E2E RMA read request";
	case CCI_E2E_MSG_RMA_READ_ACK:
		return "E2E RMA read ack";
	case CCI_E2E_MSG_MAX:
		return "E2E max (invalid)";
	}
	/* silence picky compiler */
	return NULL;
}

typedef union cci_e2e_hdr {
	/* Generic header type, used by all messages */
	struct cci_e2e_hdr_generic {
		uint8_t type;		/* Header type - must not clash with router types */
		uint8_t a[3];		/* As needed by header types */
		/* 32b */
	} generic;

	/* Generic connect request (without data ptr) */
	/* Use this struct when determining the length of a header */
	struct cci_e2e_hdr_conn_req_size {
		uint8_t type;		/* CCI_E2E_MSG_CONNECT_REQUEST */
		uint8_t version;	/* For compatability */
		uint8_t pad[2];		/* Unused for now */
		/* 32b */
	} connect_size;

	/* Connect request */
	struct cci_e2e_hdr_conn_req {
		uint8_t type;		/* CCI_E2E_MSG_CONNECT_REQUEST */
		uint8_t version;	/* For compatability */
		uint8_t pad[2];		/* Unused for now */
		/* 32b */
		char data[1];		/* Start of connect request */
	} connect;

	/* Connect reply */
	struct cci_e2e_hdr_conn_reply {
		uint8_t type;		/* CCI_E2E_MSG_CONN_REPLY */
		uint8_t status;		/* 0 for success, else errno */
		uint16_t mss;		/* Max send size */
		/* 32b */
	} conn_reply;

	/* Connect ack */
	struct cci_e2e_hdr_conn_ack {
		uint8_t type;		/* CCI_E2E_MSG_CONN_REPLY */
		uint8_t pad;		/* Unused for now */
		uint16_t mss;		/* Max send size */
		/* 32b */
	} conn_ack;

	/* Bye */
	struct cci_e2e_hdr_bye {
		uint8_t type;		/* CCI_E2E_MSG_BYE */
		uint8_t pad[3];		/* Unused for now */
		/* 32b */
	} bye;

	/* Generic send (MSG) (without data ptr) */
	struct cci_e2e_hdr_send_size {
		uint8_t type;		/* CCI_E2E_MSG_SEND */
		uint8_t pad;		/* Unused for now */
		uint16_t seq;		/* Sequence number */
		/* 32b */
	} send_size;

	/* Send (MSG) */
	struct cci_e2e_hdr_send {
		uint8_t type;		/* CCI_E2E_MSG_SEND */
		uint8_t pad;		/* Unused for now */
		uint16_t seq;		/* Sequence number */
		/* 32b */
		char data[1];		/* Start of user's payload */
	} send;

	/* Send ack (acks one sequence number only) */
	struct cci_e2e_hdr_send_ack {
		uint8_t type;		/* CCI_E2E_MSG_SEND_ACK */
		uint8_t pad;		/* Unused for now */
		uint16_t seq;		/* Ack this sequence number only */
		/* 32b */
	} send_ack;

	/* Send ack many (acks up to and including this sequence number */
	struct cci_e2e_hdr_send_ack_many {
		uint8_t type;		/* CCI_E2E_MSG_SEND_ACK_MANY */
		uint8_t pad;		/* Unused for now */
		uint16_t seq;		/* Ack this sequence number only */
		/* 32b */
	} send_ack_many;

	struct cci_e2e_hdr_send_sack {
		uint8_t type;		/* CCI_E2E_MSG_SEND_SACK */
		uint8_t count;		/* Number of SACK pairs */
		uint8_t pad[2];		/* Unused for now */
		/* 32b */
		struct send_sack {
			uint16_t start;	/* beginning ACK */
			uint16_t end;	/* ack up to and including */
		} pair[1];
	} send_sack;

	/* Send nack (nacks one sequence number only) */
	struct cci_e2e_hdr_send_nack {
		uint8_t type;		/* CCI_E2E_MSG_SEND_NACK */
		uint8_t status;		/* Reason for SEND failure */
		uint16_t seq;		/* Nack this sequence number only */
		/* 32b */
	} send_nack;

	/* For easy byte swapping to/from network order */
	uint32_t net;
} cci_e2e_hdr_t;

typedef union cci_e2e_connect {
	struct conn_req_size {
		uint32_t payload_len;	/* User's payload length */
		/* 32b */
		uint8_t dst_len;	/* Server's URI length */
		uint8_t src_len;	/* Client's URI length */
		uint8_t pad[2];		/* Unused for now */
		/* 64b */
	} size;

	struct conn_req {
		uint32_t payload_len;	/* User's payload length */
		/* 32b */
		uint8_t dst_len;	/* Server's URI length */
		uint8_t src_len;	/* Client's URI length */
		uint8_t pad[2];		/* Unused for now */
		/* 64b */
		char data[1];		/* Start of server's URI,
					   followed by client's URI,
					   followed by user's payload. */
	} request;

	uint32_t net[2];		/* For easy byte swapping */
} cci_e2e_connect_t;

static inline void
cci_e2e_pack_connect(cci_e2e_hdr_t *hdr, const char *dst, const char *src,
		const void *ptr, uint32_t len, uint32_t *total_len)
{
	cci_e2e_connect_t *connect = (cci_e2e_connect_t *)&hdr->connect.data;
	void *p = connect->request.data;

	memset(hdr, 0, sizeof(*hdr));
	hdr->connect.type = CCI_E2E_MSG_CONN_REQUEST;

	memset(connect, 0, sizeof(*connect));
	connect->request.payload_len = len;
	connect->request.dst_len = strlen(dst);
	connect->request.src_len = strlen(src);

	memcpy(p, dst, connect->request.dst_len);
	p = (void*) ((uintptr_t) p + (uintptr_t) connect->request.dst_len);
	memcpy(p, src, connect->request.src_len);
	p = (void*) ((uintptr_t) p + (uintptr_t) connect->request.src_len);
	if (len)
		memcpy(p, ptr, len);

	*total_len  = sizeof(hdr->connect_size);
	*total_len += sizeof(connect->size);
	*total_len += connect->request.payload_len;
	*total_len += connect->request.dst_len;
	*total_len += connect->request.src_len;

	hdr->net = htonl(hdr->net);
	connect->net[0] = htonl(connect->net[0]);
	connect->net[1] = htonl(connect->net[1]);
}

static inline int
cci_e2e_parse_connect(cci_e2e_hdr_t *hdr, char *dst, char *src, void **ptr, uint32_t *len)
{
	int ret = 0;
	cci_e2e_connect_t *connect = (cci_e2e_connect_t *)&(hdr->connect.data);
	void *p = connect->request.data, *q = NULL;

	/* hdr already in host order */
	connect->net[0] = htonl(connect->net[0]);
	connect->net[1] = htonl(connect->net[1]);

	memcpy(dst, p, connect->request.dst_len);
	p = (void*) ((uintptr_t) p + (uintptr_t) connect->request.dst_len);
	memcpy(src, p, connect->request.src_len);
	p = (void*) ((uintptr_t) p + (uintptr_t) connect->request.src_len);
	if (connect->request.payload_len) {
		q = calloc(1, connect->request.payload_len);
		if (!q)
			return CCI_ENOMEM;
		*len = connect->request.payload_len;
		memcpy(q, p, *len);
		*ptr = q;
	} else {
		*len = 0;
		*ptr = NULL;
	}

	return ret;
}

static inline void
cci_e2e_pack_connect_reply(cci_e2e_hdr_t *hdr, uint8_t status, uint16_t mss)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->conn_reply.type = CCI_E2E_MSG_CONN_REPLY;
	hdr->conn_reply.status = status;
	hdr->conn_reply.mss = mss;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_connect_reply(cci_e2e_hdr_t *hdr, uint8_t *status, uint16_t *mss)
{
	/* hdr already in host order */
	*status = hdr->conn_reply.status;
	*mss = hdr->conn_reply.mss;
	return;
}

static inline void
cci_e2e_pack_connect_ack(cci_e2e_hdr_t *hdr, uint16_t mss)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->conn_ack.type = CCI_E2E_MSG_CONN_ACK;
	hdr->conn_ack.mss = mss;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_connect_ack(cci_e2e_hdr_t *hdr, uint16_t *mss)
{
	/* hdr already in host order */
	*mss = hdr->conn_ack.mss;
	return;
}

static inline void
cci_e2e_pack_bye(cci_e2e_hdr_t *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->bye.type = CCI_E2E_MSG_BYE;

	hdr->net = htonl(hdr->net);
	return;
}

/* NOTE: no parse needed for BYE because there are no other fields */

static inline void
cci_e2e_pack_send(cci_e2e_hdr_t *hdr, uint16_t seq)
{
	memset(hdr, 0, sizeof(hdr->send_size));
	hdr->send.type = CCI_E2E_MSG_SEND;
	hdr->send.seq = seq;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_send(cci_e2e_hdr_t *hdr, uint16_t *seq)
{
	/* hdr already in host order */
	*seq = hdr->send.seq;
	return;
}

static inline void
cci_e2e_pack_send_ack(cci_e2e_hdr_t *hdr, uint16_t seq)
{
	memset(hdr, 0, sizeof(hdr->send_ack));
	hdr->send_ack.type = CCI_E2E_MSG_SEND_ACK;
	hdr->send_ack.seq = seq;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_send_ack(cci_e2e_hdr_t *hdr, uint16_t *seq)
{
	/* hdr already in host order */
	*seq = hdr->send_ack.seq;
	return;
}

static inline void
cci_e2e_pack_send_ack_many(cci_e2e_hdr_t *hdr, uint16_t seq)
{
	memset(hdr, 0, sizeof(hdr->send_ack_many)); /* hdr + pair[0] */
	hdr->send_ack_many.type = CCI_E2E_MSG_SEND_ACK_MANY;
	hdr->send_ack_many.seq = seq;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_send_ack_many(cci_e2e_hdr_t *hdr, uint16_t *seq)
{
	/* hdr already in host order */
	*seq = hdr->send_ack_many.seq;
	return;
}

static inline void
cci_e2e_pack_send_sack(cci_e2e_hdr_t *hdr, uint8_t count)
{
	memset(hdr, 0, sizeof(hdr->send_sack));
	hdr->send_sack.type = CCI_E2E_MSG_SEND_SACK;
	hdr->send_sack.count = count;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cc1_e2e_pack_send_sack_pair(cci_e2e_hdr_t *hdr, uint8_t index, uint16_t start, uint16_t end)
{
	uint32_t *net = (uint32_t *)&(hdr->send_sack.pair[index]);

	hdr->send_sack.pair[index].start = start;
	hdr->send_sack.pair[index].end = end;
	*net = htonl(*net);
}

static inline void
cci_e2e_parse_send_sack(cci_e2e_hdr_t *hdr, uint8_t *count)
{
	/* hdr already in host order */
	*count = hdr->send_sack.count;
	return;
}

static inline void
cc1_e2e_parse_send_sack_pair(cci_e2e_hdr_t *hdr, uint8_t index, uint16_t *start, uint16_t *end)
{
	uint32_t *net = (uint32_t *)&(hdr->send_sack.pair[index]);

	*net = ntohl(*net);
	*start = hdr->send_sack.pair[index].start;
	*end = hdr->send_sack.pair[index].end;
}

static inline void
cci_e2e_pack_send_nack(cci_e2e_hdr_t *hdr, uint8_t status, uint16_t seq)
{
	memset(hdr, 0, sizeof(hdr->send_nack));
	hdr->send_nack.type = CCI_E2E_MSG_SEND_NACK;
	hdr->send_nack.status = status;
	hdr->send_nack.seq = seq;

	hdr->net = htonl(hdr->net);
	return;
}

static inline void
cci_e2e_parse_send_nack(cci_e2e_hdr_t *hdr, uint8_t *status, uint16_t *seq)
{
	/* hdr already in host order */
	*status = hdr->send_nack.status;
	*seq = hdr->send_nack.seq;
	return;
}

static inline int
cci_e2e_parse_uri(const char *uri, uint32_t *asp, uint32_t *snp, const char **base)
{
	int ret = 0;
	uint32_t as = 0, subnet = 0;
	char *p = NULL, *dot = NULL;

	if (memcmp(uri, "e2e://", 6)) {
		ret = EINVAL;
		goto out;
	}

	p = (char*) uri + 6; /* start of as id */
	dot = strstr(p, ".");
	if (!dot) {
		ret = EINVAL;
		goto out;
	}
	*dot = '\0';
	as = strtol(p, NULL, 0);
	*dot = '.';

	p = dot + 1;
	dot = strstr(p, ".");
	if (!dot) {
		ret = EINVAL;
		goto out;
	}
	*dot = '\0';
	subnet = strtol(p, NULL, 0);
	*dot = '.';

	if (asp)
		*asp = as;
	if (snp)
		*snp = subnet;
	if (base)
		*base = dot + 1;
    out:
	return ret;
}

static inline int
cci_e2e_uri_prefix_len(const char *uri, int *len)
{
	int ret = 0;
	char *colon = NULL;

	colon = strstr(uri, "://");
	if (!colon) {
		ret = EINVAL;
		goto out;
	}

	*len = colon - uri + 3; /* include :// in the length */

    out:
	return ret;
}
#endif /* CCI_E2E_WIRE_H */
