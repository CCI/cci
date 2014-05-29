/*
 * Copyright © 2010-2013 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2013 Oak Ridge National Laboratory.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#ifndef CCI_SOCK_INTERNALS_H
#define CCI_SOCK_INTERNALS_H

#include "ctp_sock.h"

BEGIN_C_DECLS

/* Some internal return codes */
typedef enum cci_sock_status {
	CCI_SOCK_SUCCESS = 0,
	CCI_SOCK_ERROR,
	CCI_SOCK_DROP_MSG,
	CCI_SOCK_RESUME_RNR
} cci_sock_error_t;

/** Try to put a message on the wire.
 * @return -1   An error occured, the type of error is available via errno.
 * @return      Any return code different than -1 gives the number of bytes
 *              that were sent.
 */
static int sock_sendmsg(cci_os_handle_t sock, struct iovec iov[2],
                        int count, const struct sockaddr_in sin)
{
        int ret, i;
        struct msghdr msg;
        ssize_t sent = 0;

        for (i = 0; i < count; i++)
                sent += iov[i].iov_len;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void *)&sin;
        msg.msg_namelen = sizeof(sin);
        msg.msg_iov = iov;
        msg.msg_iovlen = count;

        ret = sendmsg(sock, &msg, 0);
        if (ret == -1) {
                debug(CCI_DB_MSG,
                      "%s: sendmsg() returned %d (%s) count %d iov[0] %p:%hu "
                      "iov[1] %p:%hu",
                      __func__, ret, strerror(errno), count,
                      iov[0].iov_base, (int)iov[0].iov_len,
                      iov[1].iov_base, (int)iov[1].iov_len);
        }
        debug (CCI_DB_EP, "%s: Wrote %d bytes on the socket", __func__, ret);

        return ret;
}

/**
 * @return      Return code from sock_sendmsg()
 */
static inline int
sock_sendto(cci_os_handle_t sock, void *buf, int len,
            void *rma_ptr, uint16_t rma_len,
            const struct sockaddr_in sin)
{
        int ret;
        int count = 0;
        struct iovec iov[2];

        memset(&iov, 0, sizeof(iov));
        if (buf) {
                iov[0].iov_base = buf;
                iov[0].iov_len = len;
                count = 1;
                if (rma_ptr) {
                        iov[1].iov_base = rma_ptr;
                        iov[1].iov_len = rma_len;
                        count = 2;
                        len += rma_len;
                }
        }
        ret = sock_sendmsg(sock, iov, count, sin);
        if (ret != -1)
                assert(ret == len);

        return ret;
}


/**
 * Allocate and initialize a single RX buffer.
 */
static inline sock_rx_t *
alloc_rx_buffer (cci__ep_t *ep)
{
	sock_rx_t *rx = NULL;

	rx = calloc (1, sizeof (sock_rx_t));
	if (rx == NULL)
		goto free_and_exit;
	rx->buffer = calloc (1, ep->buffer_len);
	if (rx->buffer == NULL)
		goto free_and_exit;
	rx->ctx = SOCK_CTX_RX;
	rx->evt.event.type = CCI_EVENT_RECV;
	rx->evt.ep = ep;
	ep->rx_buf_cnt++;

	return rx;

free_and_exit:
	if (rx != NULL) {
		if (rx->buffer != NULL)
			free (rx->buffer);
		free (rx);
	}

	return NULL;
}

/**
 * Update the RNR modefor a given connection. It implements the RNR semantic.
 * @param[in]	sconn	Connection for which the message was received
 * @param[in]	seq	Sequence number of the message we just received
 */
static inline int
update_rnr_mode (sock_conn_t *sconn, uint32_t seq)
{
	cci__conn_t *conn;

#if CCI_DEBUG
	assert (sconn);
#endif

	conn = sconn->conn;
	if (!cci_conn_is_reliable(conn))
		return CCI_SOCK_SUCCESS;

	if (sconn->rnr == 0) {
		/* We were not previously in a RNR state */
		debug (CCI_DB_INFO, "%s: Getting in RNR mode", __func__);
		sconn->rnr = seq;
		return CCI_SOCK_DROP_MSG;
	}

	/* If the connection is reliable/ordered we drop all messages that come
	   after the message that put us in RNR mode in the first place */
	if (conn->connection.attribute == CCI_CONN_ATTR_RO
	    && sconn->rnr != 0 && seq > sconn->rnr)
	{
		/* We just drop the message */
		debug(CCI_DB_MSG,
		      "%s: RNR connection, dropping msg (seq: %u)",
		      __func__, seq);
		return CCI_SOCK_DROP_MSG;
	}

	/* If we receive again the message that created the RNR status, we
	   resume normal operation */
	if (sconn->rnr > 0 && sconn->rnr == seq) {
		debug (CCI_DB_INFO, "%s: RNR: resuming normal operation", __func__);
		sconn->rnr = 0;
		return CCI_SOCK_RESUME_RNR;
	}

	return CCI_SOCK_SUCCESS;
}

static inline int
event_queue_is_empty (cci__ep_t *ep)
{
	int ret;
	pthread_mutex_lock(&ep->lock);
	if (TAILQ_EMPTY (&ep->evts))
		ret = 1;
	else
		ret = 0;
	pthread_mutex_unlock(&ep->lock);

	return ret;
}

static inline void
sock_queue_event (cci__ep_t *ep, cci__evt_t *evt)
{
	pthread_mutex_lock(&ep->lock);
        TAILQ_INSERT_TAIL(&ep->evts, evt, entry);
/*        evt->entry.tqe_next = NULL; */
        pthread_mutex_unlock(&ep->lock);
}

#define INIT_TX(tx) do { \
	if (tx != NULL) {		\
		tx->rma_ptr 	= NULL; \
		tx->rma_len	= 0;	\
		tx->rma_op	= NULL;	\
	}				\
} while(0)

static inline sock_tx_t*
sock_get_tx (cci__ep_t *ep)
{
	sock_ep_t *sep	= NULL;
	sock_tx_t *tx 	= NULL;

#if CCI_DEBUG
	assert (ep);
#endif

	sep = ep->priv;

	pthread_mutex_lock(&ep->lock);
        if (!TAILQ_EMPTY(&sep->idle_txs)) {
                tx = TAILQ_FIRST(&sep->idle_txs);
                TAILQ_REMOVE(&sep->idle_txs, tx, dentry);
        }
        pthread_mutex_unlock(&ep->lock);

	INIT_TX (tx);

	return tx;
}

static inline int
send_nack (sock_conn_t *sconn, sock_ep_t *sep, uint32_t seq, uint32_t ts)
{
	char            buffer[SOCK_MAX_HDR_SIZE];
	sock_header_r_t *nack_hdr;
	int             len;
	int             ret;

	nack_hdr = (sock_header_r_t*)buffer;
	if (sconn->conn->connection.attribute == CCI_CONN_ATTR_RO) {
		/* We are receiving a message out of order.
		   We keep the message to avoid retransmission
		   and we send a NACK to make sure we get the
		   message resent. */
		debug (CCI_DB_INFO,
		       "%s: recvd seq %u when %u is expected; sending NACK",
		       __func__, seq, sconn->last_recvd_seq + 1);

		sock_pack_nack (nack_hdr,
		                SOCK_MSG_NACK,
		                sconn->peer_id,
		                sconn->last_recvd_seq + 1,
		                ts, 1);
	} else {
		/* RU connection, we just want the sender to resend a specific
		   seq */
		debug (CCI_DB_INFO,
		       "%s: sending NACK for seq %u",
		       __func__, seq);

		sock_pack_nack (nack_hdr,
		                SOCK_MSG_NACK,
		                sconn->peer_id,
		                seq,
		                ts, 1);
	}

	len = sizeof (*nack_hdr);
	ret = sock_sendto (sep->sock,
	                   buffer, len,
	                   NULL,
	                   0,
	                   sconn->sin);
	if (ret == -1)
		debug (CCI_DB_MSG, "%s: NACK send failed", __func__);

	return ret;
}

END_C_DECLS

#endif /* CCI_SOCK_INTERNALS_H */
