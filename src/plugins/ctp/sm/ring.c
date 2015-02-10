/* Based on ccan/ccan/antithread/queue.
 * BSD-MIT: See LICENSE file for details. */
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sched.h>

#include "ring.h"

uint32_t ring_size(uint32_t num)
{
	ring_t r;
	return sizeof(r) + (num - 1) * sizeof(r.elems[0]);
}

void ring_init(ring_t *r, uint32_t num)
{
	r->num_elem0 = r->num_elem1 = num;
	memset(r->elems, 0, sizeof(r->elems));
	OPA_store_int(&r->tail, 0);
	OPA_store_int(&r->head, 0);
	OPA_write_barrier();
}

static inline void wait_for_change_int(OPA_int_t *ptr, int val)
{
	while (OPA_load_acquire_int(ptr) == val);
}

int ring_insert(ring_t *r, uint32_t elem)
{
	uint32_t t, h, num = r->num_elem0;

	/* Bottom bit means someone is updating now. */
	while ((h = OPA_load_acquire_int(&r->head)) & 1) {
		wait_for_change_int(&r->head, h);
	}
	t = OPA_load_acquire_int(&r->tail);

	if (h == t + (num * 2)) {
		sched_yield();
		return ENOBUFS;
	}

	/* This tells everyone we're updating. */
	if ((uint32_t)OPA_cas_int(&r->head, h, h+1) != h) {
		sched_yield();
		return EAGAIN;
	}

	OPA_store_release_int(&r->elems[(h/2) % num], elem);
	assert((uint32_t)OPA_load_acquire_int(&r->head) == h + 1);
	OPA_store_release_int(&r->head, h+2);

	return 0;
}

int ring_remove(ring_t *r, uint32_t *elemp)
{
	uint32_t h, t, num = r->num_elem1;
	uint64_t elem = 0;

	do {
		/* Read tail before head (reverse how they change) */
		t = OPA_load_acquire_int(&r->tail);
		h = OPA_load_acquire_int(&r->head);
		if ((h & ~1) == t) {
			/* Empty... */
			sched_yield();
			return EAGAIN;
		}
		elem = OPA_load_acquire_int(&r->elems[(t/2) % num]);
	} while ((uint32_t)OPA_cas_int(&r->tail, t, t+2) != t);

	*elemp = elem;
	return 0;
}
