/* This code was originally based on:
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

#ifndef SM_ATOMICS_H
#define SM_ATOMICS_H

#include <stdint.h>
#include <stdbool.h>

#ifndef __ATOMIC_RELAXED
/* If non-zero, issue full memory barrier - use clang's values */
#define __ATOMIC_RELAXED 0
#define __ATOMIC_ACQUIRE 2
#define __ATOMIC_RELEASE 3
#define __ATOMIC_SEQ_CST 5
#endif

/**
 * mb - issue full memory barrier
 */
static inline void mb(void)
{
	__sync_synchronize();
}

/**
 * read_u32 - load with optional barrier
 * @ptr: memory location
 * @barrier: barrier type
 */
static inline uint32_t read_u32(uint32_t *ptr, bool barrier)
{
	if (barrier)
		mb();
	return *(volatile uint32_t *)ptr;
}

/**
 * store_u32 - store with optional barrier
 * @ptr: memory location
 * @val: value to store
 * @barrier: barrier type
 */
static inline void store_u32(uint32_t *ptr, uint32_t val, bool barrier)
{
	*(volatile uint32_t *)ptr = val;
	if (barrier)
		mb();
}

/**
 * compare_and_swap_u32 - store with barrier
 * @ptr: memory location
 * @old: expected value
 * @val: new value to store
 * @barrier: barrier type (must not be __ATOMIC_RELAXED)
 */
static inline bool compare_and_swap_u32(uint32_t *ptr, uint32_t old, uint32_t new, bool barrier)
{
	/* the __sync_* functions issue a full barrier -
	 * keep the barrier/memmodel option for GCC atomics */
	if (0 && barrier)
		mb();
	return __sync_bool_compare_and_swap(ptr, old, new);
}

/**
 * wait_for_change_u32 - wait for the value to change
 * @ptr: memory location
 * @old: expected value
 */
static inline void wait_for_change_u32(uint32_t *ptr, uint32_t val)
{
	while (read_u32(ptr, __ATOMIC_RELAXED) == val);
}

/**
 * read_u64 - load with optional barrier
 * @ptr: memory location
 * @barrier: barrier type
 */
static inline uint64_t read_u64(uint64_t *ptr, bool barrier)
{
	if (barrier)
		mb();
	return *(volatile uint64_t *)ptr;
}

/**
 * store_u64 - store with optional barrier
 * @ptr: memory location
 * @val: value to store
 * @barrier: barrier type
 */
static inline void store_u64(uint64_t *ptr, uint64_t val, bool barrier)
{
	*(volatile uint64_t *)ptr = val;
	if (barrier)
		mb();
}

/**
 * compare_and_swap_u64 - store with barrier
 * @ptr: memory location
 * @old: expected value
 * @val: new value to store
 * @barrier: barrier type (must not be __ATOMIC_RELAXED)
 */
static inline bool compare_and_swap_u64(uint64_t *ptr, uint64_t old, uint64_t new, bool barrier)
{
	/* the __sync_* functions issue a full barrier -
	 * keep the barrier/memmodel option for GCC atomics */
	if (0 && barrier)
		mb();
	return __sync_bool_compare_and_swap(ptr, old, new);
}

#endif /* SM_ATOMICS_H */
