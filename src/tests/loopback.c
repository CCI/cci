/*
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * Copyright (c) 2011 Oak Ridge National Labs.  All rights reserved.
 * Copyright ⓒ 2012 Inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "cci.h"

int main(int argc, char *argv[])
{
	uint32_t caps = 0;
	cci_endpoint_t *endpoint = NULL;
	cci_device_t * const *devices = NULL;
	int fd;
	cci_connection_t *sconn, *cconn;
	cci_event_t *event, *ignored_connreq;
	cci_status_t ret;
	char *uri;
	struct timeval tv;
	struct iovec iov[3];
	int need_events;

	putenv("CCI_CTP_ETH_ALLOW_LOOPBACK=1");

	printf("INIT\n");

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret) {
		fprintf(stderr, "cci_init() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_devices(&devices);
	if (ret) {
		fprintf(stderr, "cci_get_devices() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_create_endpoint(NULL, 0, &endpoint, &fd);
	if (ret) {
		fprintf(stderr, "cci_create_endpoint() failed with %s\n",
			cci_strerror(endpoint, ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_opt(endpoint, CCI_OPT_ENDPT_URI, &uri);
	assert(ret == CCI_SUCCESS);

	printf("Opened %s\n", uri);

	printf("CONNECT TIMEOUT\n");

	/* connect */
	tv.tv_sec = 3;		/* so that we get some resends */
	tv.tv_usec = 0;
	ret =
	    cci_connect(endpoint, uri, "hello world!", 13,
			CCI_CONN_ATTR_RO, (void *)0xdeadbeef, 0, &tv);
	assert(ret == CCI_SUCCESS);

	/* ignore connect request */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT_REQUEST);
	assert(event->request.data_len == 13);
	assert(!strcmp(event->request.data_ptr, "hello world!"));
	printf("got data len %d data %s\n",
	       event->request.data_len, event->request.data_ptr);
	assert(event->request.attribute == CCI_CONN_ATTR_RO);
	printf("got attr %d\n", event->request.attribute);
	ret = cci_return_event(event);
	assert(ret == CCI_EINVAL);	/* cannot return connreq event without accept/reject */
	ignored_connreq = event; /* keep it for later */

	/* handle timedout event */
	/* this event could arrive before the connect request (the latter may even never arrive),
	 * but we assume it's not the case in loopback */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT);
	assert(event->connect.status == ETIMEDOUT);
	assert(event->connect.context == (void *)0xdeadbeef);
	assert(event->connect.connection == NULL);
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	printf("CONNECT REJECT\n");

	/* connect */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret =
	    cci_connect(endpoint, uri, "hello world!", 13,
			CCI_CONN_ATTR_RU, (void *)0xdeadbeef, 0, &tv);
	assert(ret == CCI_SUCCESS);

	/* handle connect request and reject it */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT_REQUEST);
	assert(event->request.data_len == 13);
	assert(!strcmp(event->request.data_ptr, "hello world!"));
	printf("got data len %d data %s\n",
	       event->request.data_len, event->request.data_ptr);
	assert(event->request.attribute == CCI_CONN_ATTR_RU);
	printf("got attr %d\n", event->request.attribute);
	ret = cci_reject(event);
	assert(ret == CCI_SUCCESS);
	ret = cci_accept(event, NULL);
	assert(ret == CCI_EINVAL);	/* cannot accept already rejected connreq */
	ret = cci_reject(event);
	assert(ret == CCI_EINVAL);	/* cannot reject already rejected connreq */
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	/* handle connect rejected */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT);
	assert(event->connect.status == ECONNREFUSED);
	assert(event->connect.context == (void *)0xdeadbeef);
	assert(event->connect.connection == NULL);
	ret = cci_accept(event, NULL);
	assert(ret == CCI_EINVAL);	/* cannot accept non-connreq event */
	ret = cci_reject(event);
	assert(ret == CCI_EINVAL);	/* cannot reject non-connreq event */
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	printf("CONNECT UU ACCEPT\n");

	/* connect */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret =
	    cci_connect(endpoint, uri, "hello world!", 13,
			CCI_CONN_ATTR_UU, (void *)0xdeadbeef, 0, &tv);
	assert(ret == CCI_SUCCESS);

	/* handle connect request and accept it */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT_REQUEST);
	assert(event->request.data_len == 13);
	assert(!strcmp(event->request.data_ptr, "hello world!"));
	printf("got data len %d data %s\n",
	       event->request.data_len, event->request.data_ptr);
	assert(event->request.attribute == CCI_CONN_ATTR_UU);
	printf("got attr %d\n", event->request.attribute);
	ret = cci_accept(event, (void *)0xfedcba98);
	assert(ret == CCI_SUCCESS);
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	need_events = 3; /* connect(1) | accept(2) */

	while (need_events) {
		while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
		assert(ret == CCI_SUCCESS);
		printf("got event type %d\n", event->type);
		if (event->type == CCI_EVENT_CONNECT) {
			/* handle connect accepted */
			assert(need_events & 1);
			need_events &= ~1;
			assert(event->connect.status == CCI_SUCCESS);
			assert(event->connect.context == (void *)0xdeadbeef);
			assert(event->connect.connection != NULL);
			cconn = event->connect.connection;
			printf("got conn %p attr %d context %p mss %d\n",
			       cconn, cconn->attribute, cconn->context, cconn->max_send_size);
			assert(cconn->endpoint == endpoint);
			assert(cconn->context == (void *)0xdeadbeef);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else if (event->type == CCI_EVENT_ACCEPT) {
			/* handle accept event */
			assert(need_events & 2);
			need_events &= ~2;
			assert(event->connect.status == CCI_SUCCESS);
			assert(event->connect.context == (void *)0xfedcba98);
			assert(event->connect.connection != NULL);
			sconn = event->connect.connection;
			printf("accepted conn %p attr %d mss %d\n",
			       sconn, sconn->attribute, sconn->max_send_size);
			assert(sconn->endpoint == endpoint);
			assert(sconn->context == (void *)0xfedcba98);
			ret = cci_accept(event, NULL);
			assert(ret == CCI_EINVAL);	/* cannot accept already accepted connreq */
			ret = cci_reject(event);
			assert(ret == CCI_EINVAL);	/* cannot reject already accepted connreq */
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else
			assert(0);
	}

	printf("UU MSG\n");

	/* send msg */
	ret = cci_send(cconn, "bye world!", 11, (void *)0x012345678, 0);
	assert(ret == CCI_SUCCESS);
	printf("send 11 bytes\n");

	need_events = 3; /* send(1) | recv(2) */

	while (need_events) {
		while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
		assert(ret == CCI_SUCCESS);
		printf("got event type %d\n", event->type);
		if (event->type == CCI_EVENT_SEND) {
			/* handle send completion */
			assert(need_events & 1);
			need_events &= ~1;
			printf("got send completion context %llx\n", event->send.context);
			assert(event->send.connection == cconn);
			assert(event->send.context == (void *)0x012345678);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else if (event->type == CCI_EVENT_RECV) {
			/* handle msg */
			assert(need_events & 2);
			need_events &= ~2;
			assert(event->recv.len == 11);
			assert(!strcmp(event->recv.ptr, "bye world!"));
			printf("got msg len %d data %s\n", event->recv.len, event->recv.ptr);
			assert(event->recv.connection == sconn);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else
			assert(0);
	}

	ret = cci_disconnect(cconn);
	assert(ret == CCI_SUCCESS);
	ret = cci_disconnect(sconn);
	assert(ret == CCI_SUCCESS);

	printf("CONNECT RO ACCEPT\n");

	/* connect */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret =
	    cci_connect(endpoint, uri, "hello world!", 13,
			CCI_CONN_ATTR_RO, (void *)0xdeadbeef, 0, &tv);
	assert(ret == CCI_SUCCESS);

	/* handle connect request and accept it */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_CONNECT_REQUEST);
	assert(event->request.data_len == 13);
	assert(!strcmp(event->request.data_ptr, "hello world!"));
	printf("got data len %d data %s\n",
	       event->request.data_len, event->request.data_ptr);
	assert(event->request.attribute == CCI_CONN_ATTR_RO);
	printf("got attr %d\n", event->request.attribute);
	ret = cci_accept(event, (void *)0xfedcba98);
	assert(ret == CCI_SUCCESS);
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	need_events = 3; /* connect(1) | accept(2) */

	while (need_events) {
		while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
		assert(ret == CCI_SUCCESS);
		printf("got event type %d\n", event->type);
		if (event->type == CCI_EVENT_CONNECT) {
			/* handle connect accepted */
			assert(need_events & 1);
			need_events &= ~1;
			assert(event->connect.status == CCI_SUCCESS);
			assert(event->connect.context == (void *)0xdeadbeef);
			assert(event->connect.connection != NULL);
			cconn = event->connect.connection;
			printf("got conn %p attr %d context %p mss %d\n",
			       cconn, cconn->attribute, cconn->context, cconn->max_send_size);
			assert(cconn->endpoint == endpoint);
			assert(cconn->context == (void *)0xdeadbeef);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else if (event->type == CCI_EVENT_ACCEPT) {
			/* handle accept event */
			assert(need_events & 2);
			need_events &= ~2;
			assert(event->connect.status == CCI_SUCCESS);
			assert(event->connect.context == (void *)0xfedcba98);
			assert(event->connect.connection != NULL);
			sconn = event->connect.connection;
			printf("accepted conn %p attr %d mss %d\n",
			       sconn, sconn->attribute, sconn->max_send_size);
			assert(sconn->endpoint == endpoint);
			assert(sconn->context == (void *)0xfedcba98);
			ret = cci_accept(event, NULL);
			assert(ret == CCI_EINVAL);	/* cannot accept already accepted connreq */
			ret = cci_reject(event);
			assert(ret == CCI_EINVAL);	/* cannot reject already accepted connreq */
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else
			assert(0);
	}

	printf("SILENT RO MSG\n");

	/* send msg */
	ret = cci_send(cconn, "bye world!", 11, (void *)0x234567890, CCI_FLAG_SILENT);
	assert(ret == CCI_SUCCESS);
	printf("send 11 bytes\n");

	/* handle msg */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_RECV);
	assert(event->recv.len == 11);
	assert(!strcmp(event->recv.ptr, "bye world!"));
	printf("got msg len %d data %s\n", event->recv.len, event->recv.ptr);
	assert(event->recv.connection == sconn);
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	printf("BLOCKING RO MSGV\n");

	/* send msg */
	iov[0].iov_base = "bye w";
	iov[0].iov_len = 5;
	iov[1].iov_base = "";
	iov[1].iov_len = 0;
	iov[2].iov_base = "orld!";
	iov[2].iov_len = 6;
	ret = cci_sendv(cconn, iov, 3, (void *)0x123456789, CCI_FLAG_BLOCKING);
	assert(ret == CCI_SUCCESS);
	printf("sendv 11 bytes\n");

	/* handle msg */
	while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
	assert(ret == CCI_SUCCESS);
	printf("got event type %d\n", event->type);
	assert(event->type == CCI_EVENT_RECV);
	assert(event->recv.len == 11);
	assert(!strcmp(event->recv.ptr, "bye world!"));
	printf("got msg len %d data %s\n", event->recv.len, event->recv.ptr);
	assert(event->recv.connection == sconn);
	ret = cci_return_event(event);
	assert(ret == CCI_SUCCESS);

	printf("RO MSG\n");

	/* send msg */
	ret = cci_send(cconn, "bye world!", 11, (void *)0x012345678, 0);
	assert(ret == CCI_SUCCESS);
	printf("send 11 bytes\n");

	need_events = 3; /* send(1) | recv(2) */

	while (need_events) {
		while ((ret = cci_get_event(endpoint, &event)) == CCI_EAGAIN) ;
		assert(ret == CCI_SUCCESS);
		printf("got event type %d\n", event->type);
		if (event->type == CCI_EVENT_SEND) {
			/* handle send completion */
			assert(need_events & 1);
			need_events &= ~1;
			printf("got send completion context %llx\n", event->send.context);
			assert(event->send.connection == cconn);
			assert(event->send.context == (void *)0x012345678);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else if (event->type == CCI_EVENT_RECV) {
			/* handle msg */
			assert(need_events & 2);
			need_events &= ~2;
			assert(event->recv.len == 11);
			assert(!strcmp(event->recv.ptr, "bye world!"));
			printf("got msg len %d data %s\n", event->recv.len, event->recv.ptr);
			assert(event->recv.connection == sconn);
			ret = cci_return_event(event);
			assert(ret == CCI_SUCCESS);
		} else
			assert(0);
	}

	free(uri);

	ret = cci_disconnect(cconn);
	assert(ret == CCI_SUCCESS);
	ret = cci_disconnect(sconn);
	assert(ret == CCI_SUCCESS);

	printf("END\n");

	/* make valgrind happy */
	ret = cci_reject(ignored_connreq);
	assert(ret == CCI_SUCCESS);
	ret = cci_return_event(ignored_connreq);
	assert(ret == CCI_SUCCESS);

	cci_destroy_endpoint(endpoint);

	cci_finalize();

	return 0;
}
