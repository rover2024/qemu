/*
 * System Call Filter Wrappers for *-user
 *
 * Copyright (c) 2019 Linaro
 * Written by Ziyang Zhang <functioner@sjtu.edu.cn>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#ifndef CONFIG_USER_ONLY
#error Cannot include this header from system emulation
#endif

#include "user/abitypes.h"
#include "qemu/plugin.h"

static inline int filter_syscall(CPUState *cpu, int num,
                                 abi_long arg1, abi_long arg2,
                                 abi_long arg3, abi_long arg4,
                                 abi_long arg5, abi_long arg6,
                                 abi_long arg7, abi_long arg8, abi_ulong *sysret)
{
    uint64_t sysret64 = 0;
    int ret = qemu_plugin_filter_syscall(cpu, num,
                             arg1, arg2, arg3, arg4,
                             arg5, arg6, arg7, arg8, &sysret64);
    if (ret != QEMU_PLUGIN_SYSCALL_FILTER_PASS) {
        *sysret = sysret64;
    }
    return ret;
}

#endif // SYSCALL_FILTER_H
