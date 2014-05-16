/* Based on ccan/ccan/antithread/queue.
 * BSD-MIT: See LICENSE file for details. */
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sched.h>

#include "ring.h"
#include "sm_atomics.h"

uint32_t ring_size(uint32_t num)
{
	ring_t r;
	return sizeof(r) + (num - 1) * sizeof(r.elems[0]);
}

void ring_init(ring_t *r, uint32_t num)
{
	r->num_elem0 = r->num_elem1 = num;
	memset(r->elems, 0, sizeof(r->elems));
	r->tail = 0;
	/* We need at least one barrier here. */
	store_u32(&r->head, 0, __ATOMIC_SEQ_CST);
}

int ring_insert(ring_t *r, uint32_t elem)
{
	uint32_t t, h, num = r->num_elem0;

	/* Bottom bit means someone is updating now. */
	while ((h = read_u32(&r->head, __ATOMIC_RELAXED)) & 1) {
		wait_for_change_u32(&r->head, h);
	}
	t = read_u32(&r->tail, __ATOMIC_RELAXED);

	if (h == t + (num * 2)) {
		sched_yield();
		return ENOBUFS;
	}

	/* This tells everyone we're updating. */
	if (!compare_and_swap_u32(&r->head, h, h+1, __ATOMIC_ACQUIRE)) {
		sched_yield();
		return EAGAIN;
	}

	store_u32(&r->elems[(h/2) % num], elem, __ATOMIC_RELAXED);
	assert(read_u32(&r->head, __ATOMIC_RELAXED) == h + 1);
	store_u32(&r->head, h+2, __ATOMIC_RELEASE);

	return 0;
}

int ring_remove(ring_t *r, uint32_t *elemp)
{
	uint32_t h, t, num = r->num_elem1;
	uint64_t elem = 0;

	do {
		/* Read tail before head (reverse how they change) */
		t = read_u32(&r->tail, __ATOMIC_SEQ_CST);
		h = read_u32(&r->head, __ATOMIC_SEQ_CST);
		if ((h & ~1) == t) {
			/* Empty... */
			sched_yield();
			return EAGAIN;
		}
		elem = read_u32(&r->elems[(t/2) % num], __ATOMIC_SEQ_CST);
	} while (!compare_and_swap_u32(&r->tail, t, t+2, __ATOMIC_SEQ_CST));

	*elemp = elem;
	return 0;
}
