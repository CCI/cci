/* This code was based on:
   https://github.com/rustyrussell/ccan/tree/antithread/ccan/antithread/queue
 */
/* Original CCAN BSD-MIT LICENSE: */
/* Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#ifndef RING_H
#define RING_H

#include <stdint.h>
#include <stdbool.h>

#define RING_CACHE_LINE	(64)
#define RING_NUM_ELEMS	(64)

typedef struct ring {
	uint32_t num_elem0;
	uint32_t head;
	char pad0[RING_CACHE_LINE - (sizeof(uint32_t) * 2)];
	uint32_t num_elem1;
	uint32_t tail;
	char pad1[RING_CACHE_LINE - (sizeof(uint32_t) * 2)];
	uint32_t elems[RING_NUM_ELEMS];
} ring_t;

/**
 * ring_size - get ring size in bytes for given number of elements.
 * @num: number of elements.
 */
uint32_t ring_size(uint32_t num);

/**
 * ring_init - initialize ring in memory
 * @r: the memory.
 */
void ring_init(ring_t *r, uint32_t num);

/**
 * ring_insert - add an element to the ring
 * @r: the ring
 * @ptr: the pointer to add
 */
int ring_insert(ring_t *r, uint32_t elem);

/**
 * ring_remove - remove an element to the ring
 * @r: the ring
 */
int ring_remove(ring_t *r, uint32_t *elem);

#endif /* RING_H */
