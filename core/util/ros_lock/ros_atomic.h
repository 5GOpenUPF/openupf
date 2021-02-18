/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#ifndef _ROS_ATOMIC_H_
#define _ROS_ATOMIC_H_

#include <emmintrin.h>

//#define MPLOCKED                    /**< No need to insert MP lock prefix. */
#define MPLOCKED        "lock ; "   /**< Insert MP lock prefix. */

/*------------------------- 16 bit atomic operations -------------------------*/
/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int16_t cnt; /**< An internal counter value. */
} ros_atomic16_t;

/**
 * Static initializer for an atomic counter.
 */
#define ROS_ATOMIC16_INIT(val) { (val) }

/**
 * Atomic compare and set.
 *
 * (atomic) equivalent to:
 *   if (*dst == exp)
 *     *dst = src (all 16-bit words)
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param exp
 *   The expected value.
 * @param src
 *   The new value.
 * @return
 *   Non-zero on success; 0 on failure.
 */
static inline int
ros_atomic16_cmpset(volatile uint16_t *dst, uint16_t exp, uint16_t src)
{
	uint8_t res;

	asm volatile(
			MPLOCKED
			"cmpxchgw %[src], %[dst];"
			"sete %[res];"
			: [res] "=a" (res),     /* output */
			  [dst] "=m" (*dst)
			: [src] "r" (src),      /* input */
			  "a" (exp),
			  "m" (*dst)
			: "memory");            /* no-clobber list */
	return res;
}

/**
 * Atomic exchange.
 *
 * (atomic) equivalent to:
 *   ret = *dst
 *   *dst = val;
 *   return ret;
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param val
 *   The new value.
 * @return
 *   The original value at that location
 */
static inline uint16_t
ros_atomic16_exchange(volatile uint16_t *dst, uint16_t val)
{
	asm volatile(
			MPLOCKED
			"xchgw %0, %1;"
			: "=r" (val), "=m" (*dst)
			: "0" (val),  "m" (*dst)
			: "memory");         /* no-clobber list */
	return val;
}

/**
 * Initialize an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
ros_atomic16_init(ros_atomic16_t *v)
{
	v->cnt = 0;
}

/**
 * Atomically read a 16-bit value from a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   The value of the counter.
 */
static inline int16_t
ros_atomic16_read(const ros_atomic16_t *v)
{
	return v->cnt;
}

/**
 * Atomically set a counter to a 16-bit value.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param new_value
 *   The new value for the counter.
 */
static inline void
ros_atomic16_set(ros_atomic16_t *v, int16_t new_value)
{
	v->cnt = new_value;
}

/**
 * Atomically add a 16-bit value to an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 */
static inline void
ros_atomic16_add(ros_atomic16_t *v, int16_t inc)
{
	__sync_fetch_and_add(&v->cnt, inc);
}

/**
 * Atomically subtract a 16-bit value from an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 */
static inline void
ros_atomic16_sub(ros_atomic16_t *v, int16_t dec)
{
	__sync_fetch_and_sub(&v->cnt, dec);
}

/**
 * Atomically increment a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
ros_atomic16_inc(ros_atomic16_t *v)
{
	asm volatile(
			MPLOCKED
			"incw %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

/**
 * Atomically decrement a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
ros_atomic16_dec(ros_atomic16_t *v)
{
	asm volatile(
			MPLOCKED
			"decw %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

/**
 * Atomically add a 16-bit value to a counter and return the result.
 *
 * Atomically adds the 16-bits value (inc) to the atomic counter (v) and
 * returns the value of v after addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static inline int16_t
ros_atomic16_add_return(ros_atomic16_t *v, int16_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

/**
 * Atomically subtract a 16-bit value from a counter and return
 * the result.
 *
 * Atomically subtracts the 16-bit value (inc) from the atomic counter
 * (v) and returns the value of v after the subtraction.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 * @return
 *   The value of v after the subtraction.
 */
static inline int16_t
ros_atomic16_sub_return(ros_atomic16_t *v, int16_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

/**
 * Atomically increment a 16-bit counter by one and test.
 *
 * Atomically increments the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the increment operation is 0; false otherwise.
 */
static inline int ros_atomic16_inc_and_test(ros_atomic16_t *v)
{
	uint8_t ret;

	asm volatile(
			MPLOCKED
			"incw %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt),  /* output */
			  [ret] "=qm" (ret)
			);
	return ret != 0;
}

/**
 * Atomically decrement a 16-bit counter by one and test.
 *
 * Atomically decrements the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the decrement operation is 0; false otherwise.
 */
static inline int ros_atomic16_dec_and_test(ros_atomic16_t *v)
{
	uint8_t ret;

	asm volatile(MPLOCKED
			"decw %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt),  /* output */
			  [ret] "=qm" (ret)
			);
	return ret != 0;
}

/**
 * Atomically test and set a 16-bit atomic counter.
 *
 * If the counter value is already set, return 0 (failed). Otherwise, set
 * the counter value to 1 and return 1 (success).
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   0 if failed; else 1, success.
 */
static inline int ros_atomic16_test_and_set(ros_atomic16_t *v)
{
	return ros_atomic16_cmpset((volatile uint16_t *)&v->cnt, 0, 1);
}

/**
 * Atomically set a 16-bit counter to 0.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void ros_atomic16_clear(ros_atomic16_t *v)
{
	v->cnt = 0;
}

/*------------------------- 32 bit atomic operations -------------------------*/
/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int32_t cnt; /**< An internal counter value. */
} ros_atomic32_t;

/**
 * Static initializer for an atomic counter.
 */
#define ROS_ATOMIC32_INIT(val) { (val) }

static inline int
ros_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	uint8_t res;

	asm volatile(
			MPLOCKED
			"cmpxchgl %[src], %[dst];"
			"sete %[res];"
			: [res] "=a" (res),     /* output */
			  [dst] "=m" (*dst)
			: [src] "r" (src),      /* input */
			  "a" (exp),
			  "m" (*dst)
			: "memory");            /* no-clobber list */
	return res;
}

static inline uint32_t
ros_atomic32_exchange(volatile uint32_t *dst, uint32_t val)
{
	asm volatile(
			MPLOCKED
			"xchgl %0, %1;"
			: "=r" (val), "=m" (*dst)
			: "0" (val),  "m" (*dst)
			: "memory");         /* no-clobber list */
	return val;
}

/**
 * Initialize an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
ros_atomic32_init(ros_atomic32_t *v)
{
	v->cnt = 0;
}

/**
 * Atomically read a 32-bit value from a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   The value of the counter.
 */
static inline int32_t
ros_atomic32_read(const ros_atomic32_t *v)
{
	return v->cnt;
}

/**
 * Atomically set a counter to a 32-bit value.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param new_value
 *   The new value for the counter.
 */
static inline void
ros_atomic32_set(ros_atomic32_t *v, int32_t new_value)
{
	v->cnt = new_value;
}

/**
 * Atomically add a 32-bit value to an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 */
static inline void
ros_atomic32_add(ros_atomic32_t *v, int32_t inc)
{
	__sync_fetch_and_add(&v->cnt, inc);
}

/**
 * Atomically subtract a 32-bit value from an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 */
static inline void
ros_atomic32_sub(ros_atomic32_t *v, int32_t dec)
{
	__sync_fetch_and_sub(&v->cnt, dec);
}

static inline void
ros_atomic32_inc(ros_atomic32_t *v)
{
	asm volatile(
			MPLOCKED
			"incl %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

static inline void
ros_atomic32_dec(ros_atomic32_t *v)
{
	asm volatile(
			MPLOCKED
			"decl %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

/**
 * Atomically add a 32-bit value to a counter and return the result.
 *
 * Atomically adds the 32-bits value (inc) to the atomic counter (v) and
 * returns the value of v after addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static inline int32_t
ros_atomic32_add_return(ros_atomic32_t *v, int32_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

/**
 * Atomically subtract a 32-bit value from a counter and return
 * the result.
 *
 * Atomically subtracts the 32-bit value (inc) from the atomic counter
 * (v) and returns the value of v after the subtraction.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 * @return
 *   The value of v after the subtraction.
 */
static inline int32_t
ros_atomic32_sub_return(ros_atomic32_t *v, int32_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

static inline int ros_atomic32_inc_and_test(ros_atomic32_t *v)
{
	uint8_t ret;

	asm volatile(
			MPLOCKED
			"incl %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt),  /* output */
			  [ret] "=qm" (ret)
			);
	return ret != 0;
}

static inline int ros_atomic32_dec_and_test(ros_atomic32_t *v)
{
	uint8_t ret;

	asm volatile(MPLOCKED
			"decl %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt),  /* output */
			  [ret] "=qm" (ret)
			);
	return ret != 0;
}

static inline int ros_atomic32_test_and_set(ros_atomic32_t *v)
{
	return ros_atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

/**
 * Atomically set a 32-bit counter to 0.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void ros_atomic32_clear(ros_atomic32_t *v)
{
	v->cnt = 0;
}

/*------------------------- 64 bit atomic operations -------------------------*/
/**
 * The atomic counter structure.
 */
typedef struct {
	volatile int64_t cnt;  /**< Internal counter value. */
} ros_atomic64_t;

/**
 * Static initializer for an atomic counter.
 */
#define ROS_ATOMIC64_INIT(val) { (val) }

static inline int
ros_atomic64_cmpset(volatile uint64_t *dst, uint64_t exp, uint64_t src)
{
	uint8_t res;


	asm volatile(
			MPLOCKED
			"cmpxchgq %[src], %[dst];"
			"sete %[res];"
			: [res] "=a" (res),     /* output */
			  [dst] "=m" (*dst)
			: [src] "r" (src),      /* input */
			  "a" (exp),
			  "m" (*dst)
			: "memory");            /* no-clobber list */

	return res;
}

static inline uint64_t
ros_atomic64_exchange(volatile uint64_t *dst, uint64_t val)
{
	asm volatile(
			MPLOCKED
			"xchgq %0, %1;"
			: "=r" (val), "=m" (*dst)
			: "0" (val),  "m" (*dst)
			: "memory");         /* no-clobber list */
	return val;
}

static inline void
ros_atomic64_init(ros_atomic64_t *v)
{
	v->cnt = 0;
}

static inline int64_t
ros_atomic64_read(ros_atomic64_t *v)
{
	return v->cnt;
}

static inline void
ros_atomic64_set(ros_atomic64_t *v, int64_t new_value)
{
	v->cnt = new_value;
}

static inline void
ros_atomic64_add(ros_atomic64_t *v, int64_t inc)
{
	asm volatile(
			MPLOCKED
			"addq %[inc], %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: [inc] "ir" (inc),     /* input */
			  "m" (v->cnt)
			);
}

static inline void
ros_atomic64_sub(ros_atomic64_t *v, int64_t dec)
{
	asm volatile(
			MPLOCKED
			"subq %[dec], %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: [dec] "ir" (dec),     /* input */
			  "m" (v->cnt)
			);
}

static inline void
ros_atomic64_inc(ros_atomic64_t *v)
{
	asm volatile(
			MPLOCKED
			"incq %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

static inline void
ros_atomic64_dec(ros_atomic64_t *v)
{
	asm volatile(
			MPLOCKED
			"decq %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
}

static inline int64_t
ros_atomic64_add_return(ros_atomic64_t *v, int64_t inc)
{
	int64_t prev = inc;

	asm volatile(
			MPLOCKED
			"xaddq %[prev], %[cnt]"
			: [prev] "+r" (prev),   /* output */
			  [cnt] "=m" (v->cnt)
			: "m" (v->cnt)          /* input */
			);
	return prev + inc;
}

static inline int64_t
ros_atomic64_sub_return(ros_atomic64_t *v, int64_t dec)
{
	return ros_atomic64_add_return(v, -dec);
}

static inline int ros_atomic64_inc_and_test(ros_atomic64_t *v)
{
	uint8_t ret;

	asm volatile(
			MPLOCKED
			"incq %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt), /* output */
			  [ret] "=qm" (ret)
			);

	return ret != 0;
}

static inline int ros_atomic64_dec_and_test(ros_atomic64_t *v)
{
	uint8_t ret;

	asm volatile(
			MPLOCKED
			"decq %[cnt] ; "
			"sete %[ret]"
			: [cnt] "+m" (v->cnt),  /* output */
			  [ret] "=qm" (ret)
			);
	return ret != 0;
}

static inline int ros_atomic64_test_and_set(ros_atomic64_t *v)
{
	return ros_atomic64_cmpset((volatile uint64_t *)&v->cnt, 0, 1);
}

static inline void ros_atomic64_clear(ros_atomic64_t *v)
{
	v->cnt = 0;
}

#endif /* _ROS_ATOMIC_H_ */

