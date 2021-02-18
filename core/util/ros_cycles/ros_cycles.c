/***************************************************************
 Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.
 SPDX-License-Identifier: Apache-2.0
 ***************************************************************/

#include "common.h"
#include "util.h"
#include <time.h>
#include <cpuid.h>
#include <inttypes.h>
#include "ros_cycles.h"

/* The frequency of the RDTSC timer resolution */
static uint64_t ros_tsc_resolution_hz;

/* Frequency per millisecond */
static uint64_t ros_tsc_hz_per_ms;

static unsigned int
ros_cpu_get_model(uint32_t fam_mod_step)
{
	uint32_t family, model, ext_model;

	family = (fam_mod_step >> 8) & 0xf;
	model = (fam_mod_step >> 4) & 0xf;

	if (family == 6 || family == 15) {
		ext_model = (fam_mod_step >> 16) & 0xf;
		model += (ext_model << 4);
	}

	return model;
}

static int32_t
rdmsr(int msr, uint64_t *val)
{
	int fd;
	int ret;

	fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (fd < 0)
		return fd;

	ret = pread(fd, val, sizeof(uint64_t), msr);

	close(fd);
	return ret;
}

static uint32_t
check_model_wsm_nhm(uint8_t model)
{
	switch (model) {
	/* Westmere */
	case 0x25:
	case 0x2C:
	case 0x2F:
	/* Nehalem */
	case 0x1E:
	case 0x1F:
	case 0x1A:
	case 0x2E:
		return 1;
	}

	return 0;
}

static uint32_t
check_model_gdm_dnv(uint8_t model)
{
	switch (model) {
	/* Goldmont */
	case 0x5C:
	/* Denverton */
	case 0x5F:
		return 1;
	}

	return 0;
}

static uint64_t
get_tsc_freq_arch(void)
{
	uint64_t tsc_hz = 0;
	uint32_t a, b, c, d, maxleaf;
	uint8_t mult, model;
	int32_t ret;

	/*
	 * Time Stamp Counter and Nominal Core Crystal Clock
	 * Information Leaf
	 */
	maxleaf = __get_cpuid_max(0, NULL);

	if (maxleaf >= 0x15) {
		__cpuid(0x15, a, b, c, d);

		/* EBX : TSC/Crystal ratio, ECX : Crystal Hz */
		if (b && c)
			return c * (b / a);
	}

	__cpuid(0x1, a, b, c, d);
	model = ros_cpu_get_model(a);

	if (check_model_wsm_nhm(model))
		mult = 133;
	else if ((c & bit_AVX) || check_model_gdm_dnv(model))
		mult = 100;
	else
		return 0;

	ret = rdmsr(0xCE, &tsc_hz);
	if (ret < 0)
		return 0;

	return ((tsc_hz >> 8) & 0xff) * mult * 1E6;
}

static uint64_t
get_tsc_freq(void)
{
#define NS_PER_SEC 1E9

	struct timespec sleeptime = {.tv_nsec = NS_PER_SEC / 10 }; /* 1/10 second */

	struct timespec t_start, t_end;
	uint64_t tsc_hz;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
		uint64_t ns, end, start = ros_rdtsc();
		nanosleep(&sleeptime,NULL);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		end = ros_rdtsc();
		ns = ((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
		ns += (t_end.tv_nsec - t_start.tv_nsec);

		double secs = (double)ns/NS_PER_SEC;
		tsc_hz = (uint64_t)((end - start)/secs);
		return tsc_hz;
	}
	return 0;
}

static uint64_t
estimate_tsc_freq(void)
{
	/* TSC frequency estimated roughly clock timings may be less accurate. */
	/* assume that the sleep(1) will sleep for 1 second */
	uint64_t start = ros_rdtsc();
	sleep(1);
	return ros_rdtsc() - start;
}

uint64_t
ros_get_tsc_hz(void)
{
	return ros_tsc_resolution_hz;
}

uint64_t
ros_get_futurn_tsc(uint64_t ms)
{
	uint64_t inc_tsc = ros_tsc_hz_per_ms * ms;

    return (ros_rdtsc() + inc_tsc);
}

void
ros_set_tsc_freq(void)
{
	uint64_t freq;

	freq = get_tsc_freq_arch();
	if (!freq)
		freq = get_tsc_freq();
	if (!freq)
		freq = estimate_tsc_freq();

	ros_tsc_resolution_hz = freq;
    ros_tsc_hz_per_ms = ros_tsc_resolution_hz / 1000;
}

