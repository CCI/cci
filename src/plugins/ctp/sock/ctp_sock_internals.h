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

END_C_DECLS

#endif /* CCI_SOCK_INTERNALS_H */
