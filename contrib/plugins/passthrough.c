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
#include <gmodule.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum {
    SyscallPathThroughNumber = 4096,
};

enum SyscallPassThroughID {
    SPID_GetHostAttribute = 1,
    SPID_LoadLibrary,
    SPID_FreeLibrary,
    SPID_GetProcAddress,
    SPID_GetErrorMessage,
    SPID_InvokeProc,
};

/// ClientCallingConvention - Calling conventions for \c SPID_InvokeProc.
enum ClientCallingConvention {
    /// The standard calling convention, where all arguments are passed through pointer on
    /// the stack.
    /// \code
    ///     void (void **args, void *ret, void *metadata)
    /// \endcode
    CC_Standard = 0,
};

/// InvocationArguments - Arguments for invoking a function.
struct InvocationArguments {
    int conv;
    union {
        struct {
            void *proc;
            void **args;
            void *ret;
            void *metadata;
        } standard;
    };
};

static const char *query_host_attribute(const char *key)
{
    if (strcmp(key, "emu") == 0) {
        return "qemu";
    }

    if (strcmp(key, "dispatcher") == 0) {
        return "qemu-passthrough-plugin";
    }

    return NULL;
}

static void invoke_proc(const struct InvocationArguments *ia)
{
    assert(ia->conv == CC_Standard);

    typedef void (*Func)(void ** /*args*/, void * /*ret*/, void * /*metadata*/);
    Func func = (Func) ia->standard.proc;
    func(ia->standard.args, ia->standard.ret, ia->standard.metadata);
}

struct QemuPassThroughContext {
    /// Extra dispatch function for magic system calls.
    qemu_plugin_vcpu_syscall_filter_cb_t dispatch;

    /// Current syscall number, set on each syscall filter and unset on each
    /// syscall return.
    int64_t cur_syscall_num;
};

QEMU_PLUGIN_EXPORT struct QemuPassThroughContext qemu_passthrough_ctx;

static bool vcpu_syscall_filter(qemu_plugin_id_t id, unsigned int vcpu_index,
                                int64_t num, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5,
                                uint64_t a6, uint64_t a7, uint64_t a8,
                                uint64_t *sysret)
{
    qemu_passthrough_ctx.cur_syscall_num = num;

    if (num == SyscallPathThroughNumber) {
        if (qemu_passthrough_ctx.dispatch &&
            qemu_passthrough_ctx.dispatch(id, vcpu_index, num, a1, a2, a3,
                                          a4, a5, a6, a7, a8, sysret)) {
            return true;
        }

        int spid = a1;
        void **args = (void **) a2;
        void *ret = (void *) a3;
        switch (spid) {
            case SPID_GetHostAttribute: {
                assert(args);

                const char **attr_ptr = (const char **) ret;
                assert(attr_ptr);

                const char *key = (const char *) args[0];
                *attr_ptr = query_host_attribute(key);

                *sysret = 0;
                break;
            }

            case SPID_LoadLibrary: {
                void **handle_ptr = (void **) ret;
                assert(handle_ptr);

                assert(args);
                const char *path = (const char *) args[0];
                const int flags = (int) (uintptr_t) args[1];
                *handle_ptr = g_module_open(path, flags);

                *sysret = 0;
                break;
            }

            case SPID_FreeLibrary: {
                int *success = (int *) ret;
                assert(success);

                assert(args);
                void *handle = args[0];

                *success = g_module_close(handle);

                *sysret = 0;
                break;
            }

            case SPID_GetProcAddress: {
                void **entry_ptr = (void **) ret;
                assert(entry_ptr);

                assert(args);
                void *handle = args[0];
                const char *name = (const char *) args[1];
                if (!g_module_symbol(handle, name, entry_ptr)) {
                    entry_ptr = NULL;
                }

                *sysret = 0;
                break;
            }

            case SPID_GetErrorMessage: {
                char **error_ptr = (char **) ret;
                assert(error_ptr);

                *error_ptr = (char *) g_module_error();

                *sysret = 0;
                break;
            }

            case SPID_InvokeProc: {
                const struct InvocationArguments *ia = (const struct InvocationArguments *) args[0];
                assert(ia);

                invoke_proc(ia);

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

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    qemu_passthrough_ctx.cur_syscall_num = -1;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    qemu_plugin_register_vcpu_syscall_filter_cb(id, vcpu_syscall_filter);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    return 0;
}
