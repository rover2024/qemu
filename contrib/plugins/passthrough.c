/*
 * Copyright (C) 2026, Ziyang Zhang <functioner@sjtu.edu.cn>
 *
 * Passthrough Plugin: Allows guest to invoke host functions by
 * invoking magic system calls.
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <string.h>
#include <dlfcn.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* The magic system call number for pass-through. */
enum {
    SyscallPathThroughNumber = 4096,
};

/* The pass-through call ID. */
enum SyscallPassThroughID {
    SPID_GetHostAttribute,
    SPID_LoadLibrary,
    SPID_GetProcAddress,
    SPID_FreeLibrary,
    SPID_GetLibraryError,
    SPID_InvokeProc,
};

static inline const char *query_host_attribute(const char *key)
{
    if (strcmp(key, "emu") == 0) {
        return "qemu";
    }
    return NULL;
}

static inline void invoke_proc(void *proc, void *arg1, void *arg2) {
    typedef void (*Func)(void * /*arg1*/, void * /*arg2*/);
    Func func = (Func) proc;
    func(arg1, arg2);
}

static bool vcpu_syscall_filter(qemu_plugin_id_t id, unsigned int vcpu_index,
                                int64_t num, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5,
                                uint64_t a6, uint64_t a7, uint64_t a8,
                                uint64_t *sysret)
{
    if (num == SyscallPathThroughNumber) {
        switch (a1) {
            /* Query host attribute by a reserved key. */
            case SPID_GetHostAttribute: {
                const char *key       = (const char *)  a2;
                const char **attr_ptr = (const char **) a3;
                assert(attr_ptr);
                *attr_ptr = query_host_attribute(key);
                *sysret = 0;
                break;
            }

            /* Load a shared library. */
            case SPID_LoadLibrary: {
                const char *path  = (const char *) a2;
                int flags         = (int) a3;
                void **handle_ptr = (void **) a4;
                assert(handle_ptr);
                *handle_ptr = dlopen(path, flags);
                *sysret = 0;
                break;
            }

            /* Get the address of a function in a shared library. */
            case SPID_GetProcAddress: {
                void *handle     = (void *) a2;
                const char *name = (const char *) a3;
                void **entry_ptr = (void **) a4;
                assert(entry_ptr);
                *entry_ptr = dlsym(handle, name);
                *sysret = 0;
                break;
            }

            /* Free a shared library. */
            case SPID_FreeLibrary: {
                void *handle = (void *) a2;
                int *ret_ptr = (int *) a3;
                *ret_ptr = dlclose(handle);
                *sysret = 0;
                break;
            }

            /* Get the last error message for a library event. */
            case SPID_GetLibraryError: {
                const char **error_ptr = (const char **) a2;
                *error_ptr = dlerror();
                *sysret = 0;
                break;
            }

            /* Invoke a function of a common interface. */
            case SPID_InvokeProc: {
                void *proc = (void *) a2;
                void *arg1 = (void *) a3;
                void *arg2 = (void *) a4;
                assert(proc);
                invoke_proc(proc, arg1, arg2);
                *sysret = 0;
                break;
            }

            default: {
                *sysret = EINVAL;
                break;
            }
        }
        return true;
    }
    return false;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    qemu_plugin_register_vcpu_syscall_filter_cb(id, vcpu_syscall_filter);
    return 0;
}
