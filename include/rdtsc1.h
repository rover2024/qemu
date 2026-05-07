#pragma once

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

enum RDTSC_DATA_PHASE {
    RDP_INVALID,
    RDP_GTL_START,
    RDP_GTL_END,
    RDP_SYSCALL_HELPER,
    RDP_HOST_START,
    RDP_HOST_END,
};

struct RDTSC_DATA {
    enum RDTSC_DATA_PHASE phase;

    uint64_t last_tick;

    uint64_t gtl_ticks;
    uint64_t syscall_ticks;
    uint64_t dispatch_ticks;
    uint64_t host_ticks;
};

extern struct RDTSC_DATA rdtsc_data;

static inline uint64_t rdtsc(void) {
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#elif defined(__riscv)
    uint64_t cycles;
    __asm__ __volatile__("rdcycle %0" : "=r"(cycles));
    return cycles;
#else
#error "Unsupported architecture"
#endif
}

static inline void  rdtsc_over(void) {
    printf("rdtsc_over\n");
    printf("gtl_ticks: %" PRIu64 "\n", rdtsc_data.gtl_ticks);
    printf("syscall_ticks: %" PRIu64 "\n", rdtsc_data.syscall_ticks);
    printf("dispatch_ticks: %" PRIu64 "\n", rdtsc_data.dispatch_ticks);
    printf("host_ticks: %" PRIu64 "\n", rdtsc_data.host_ticks);
}
