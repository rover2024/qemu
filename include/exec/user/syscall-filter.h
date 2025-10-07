/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * TODO
 */

#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

struct CPUState;

struct CPUArchState;

typedef enum syscall_filter_ret {
    SYSCALL_FILTER_IGNORE,
    SYSCALL_FILTER_HANDLED,
    SYSCALL_FILTER_EXIT,
} syscall_filter_ret;

typedef struct SyscallFilterContext {
    void (*reentry)(struct CPUArchState *);
    struct CPUState *(*get_thread_cpu)(void);
} SyscallFilterContext;

typedef struct SyscallFilter {
    int syscall_num; // special syscall number to filter
    int (*handler)(SyscallFilterContext *, struct CPUArchState *);
} SyscallFilter;

extern SyscallFilter *syscall_filter;

#endif // SYSCALL_FILTER_H