/*
 *  qemu user cpu loop
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "qemu/timer.h"
#include "user-internals.h"
#include "cpu_loop-common.h"
#include "signal-common.h"
#include "user-mmap.h"

/***********************************************************/
/* CPUX86 core interface */

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_host_ticks();
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
              int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;

static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}

#ifdef TARGET_X86_64
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl, bool is64)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}
#else
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
                     uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl, bool is64)
{
    if (is64) {
        set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
    } else {
        set_gate(idt_table + n, 0, dpl, 0, 0);
    }
}
#endif

#ifdef TARGET_X86_64
static bool write_ok_or_segv(CPUX86State *env, abi_ptr addr, size_t len)
{
    /*
     * For all the vsyscalls, NULL means "don't write anything" not
     * "write it at address 0".
     */
    if (addr == 0 || access_ok(env_cpu(env), VERIFY_WRITE, addr, len)) {
        return true;
    }

    env->error_code = PG_ERROR_W_MASK | PG_ERROR_U_MASK;
    force_sig_fault(TARGET_SIGSEGV, TARGET_SEGV_MAPERR, addr);
    return false;
}

/*
 * Since v3.1, the kernel traps and emulates the vsyscall page.
 * Entry points other than the official generate SIGSEGV.
 */
static void emulate_vsyscall(CPUX86State *env)
{
    int syscall;
    abi_ulong ret;
    uint64_t caller;

    /*
     * Validate the entry point.  We have already validated the page
     * during translation to get here; now verify the offset.
     */
    switch (env->eip & ~TARGET_PAGE_MASK) {
    case 0x000:
        syscall = TARGET_NR_gettimeofday;
        break;
    case 0x400:
        syscall = TARGET_NR_time;
        break;
    case 0x800:
        syscall = TARGET_NR_getcpu;
        break;
    default:
        goto sigsegv;
    }

    /*
     * Validate the return address.
     * Note that the kernel treats this the same as an invalid entry point.
     */
    if (get_user_u64(caller, env->regs[R_ESP])) {
        goto sigsegv;
    }

    /*
     * Validate the pointer arguments.
     */
    switch (syscall) {
    case TARGET_NR_gettimeofday:
        if (!write_ok_or_segv(env, env->regs[R_EDI],
                              sizeof(struct target_timeval)) ||
            !write_ok_or_segv(env, env->regs[R_ESI],
                              sizeof(struct target_timezone))) {
            return;
        }
        break;
    case TARGET_NR_time:
        if (!write_ok_or_segv(env, env->regs[R_EDI], sizeof(abi_long))) {
            return;
        }
        break;
    case TARGET_NR_getcpu:
        if (!write_ok_or_segv(env, env->regs[R_EDI], sizeof(uint32_t)) ||
            !write_ok_or_segv(env, env->regs[R_ESI], sizeof(uint32_t))) {
            return;
        }
        break;
    default:
        g_assert_not_reached();
    }

    /*
     * Perform the syscall.  None of the vsyscalls should need restarting.
     */
    ret = do_syscall(env, syscall, env->regs[R_EDI], env->regs[R_ESI],
                     env->regs[R_EDX], env->regs[10], env->regs[8],
                     env->regs[9], 0, 0);
    g_assert(ret != -QEMU_ERESTARTSYS);
    g_assert(ret != -QEMU_ESIGRETURN);
    if (ret == -TARGET_EFAULT) {
        goto sigsegv;
    }
    env->regs[R_EAX] = ret;

    /* Emulate a ret instruction to leave the vsyscall page.  */
    env->eip = caller;
    env->regs[R_ESP] += 8;
    return;

 sigsegv:
    force_sig(TARGET_SIGSEGV);
}
#endif

static bool maybe_handle_vm86_trap(CPUX86State *env, int trapnr)
{
#ifndef TARGET_X86_64
    if (env->eflags & VM_MASK) {
        handle_vm86_trap(env, trapnr);
        return true;
    }
#endif
    return false;
}

// =================================================================================
// lorelei/lorehapi.h

#include <dlfcn.h>
#include <link.h>

typedef void      (*FP_ExecuteCallback)(void * /*thunk*/, void * /*callback*/, void * /*args*/, void * /*ret*/, void * /*metadata*/);
typedef pthread_t (*FP_GetLastPThreadId)(void);
typedef void      (*FP_NotifyPThreadCreate)(pthread_t * /*thread*/, const pthread_attr_t * /*attr*/, void *(*) (void *) /*start_routine*/, void * /*arg*/, int * /*ret*/);
typedef void      (*FP_NotifyPThreadExit)(void * /*ret*/);
typedef void      (*FP_NotifyHostLibraryOpen)(const char * /*identifier*/);

struct LoreEmuApis {
    // Executes guest callback
    FP_ExecuteCallback ExecuteCallback;

    // Get last pthread id
    FP_GetLastPThreadId GetLastPThreadId;

    // Notify emulator to create thread in guest environment
    FP_NotifyPThreadCreate NotifyPThreadCreate;

    // Notify emulator to exit thread in guest environment
    FP_NotifyPThreadExit NotifyPThreadExit;

    // Notify guest runtime to load GTL
    FP_NotifyHostLibraryOpen NotifyHostLibraryOpen;
};

typedef struct LoreEmuApis *(*FP_HrtGetEmuApis)(void);
typedef void                (*FP_HandleExtraGuestCall)(int /*type*/, void ** /*args*/, void * /*ret*/);

struct LORE_EMU_CONTEXT {
    void *LibraryHandle;

    FP_HrtGetEmuApis HrtGetEmuApis;
    FP_HandleExtraGuestCall HandleExtraGuestCall;
};

static struct LORE_EMU_CONTEXT LoreEmuContext = {};

static __thread union LOREUSER_PROC_NEXTCALL *LoreThreadNextCall = NULL;

__thread struct LORE_HOST_THREAD_CONTEXT LoreHostThreadContext;

// =================================================================================


// =================================================================================
// lorelei/loreuser.h

#define LOREUSER_SYSCALL_NUM 114514

enum LOREUSER_CALL_TYPE {
    LOREUSER_CT_CheckHealth,

    LOREUSER_CT_LoadLibrary,
    LOREUSER_CT_FreeLibrary,
    LOREUSER_CT_GetProcAddress,
    LOREUSER_CT_GetErrorMessage,
    LOREUSER_CT_GetModulePath,
    LOREUSER_CT_GetAddressBoundary,

    LOREUSER_CT_InvokeHostProc,
    LOREUSER_CT_ResumeHostProc, // internal

    LOREUSER_CT_GetLibraryData,
    LOREUSER_CT_CallHostHelper,

    // internal
    LOREUSER_CT_LA_ObjOpen,
    LOREUSER_CT_LA_ObjClose,
    LOREUSER_CT_LA_PreInit,
    LOREUSER_CT_LA_SymBind,
};

enum LOREUSER_PROC_RESULT {
    LOREUSER_PR_Finished = 0,
    LOREUSER_PR_Callback,
    LOREUSER_PR_PThreadCreate,
    LOREUSER_PR_PThreadExit,
    LOREUSER_PR_HostLibraryOpen,
};

enum LOREUSER_PROC_CONVENTION {
    LOREUSER_PC_Function,
    LOREUSER_PC_ThreadEntry,
    LOREUSER_PC_HostCallback,
};

enum LOREUESR_HELPER_ID {
    LOREUSER_HI_ExtractPrintFArgs = 1,
    LOREUSER_HI_ExtractSScanFArgs,
};

union LOREUSER_PROC_NEXTCALL {
    // LOREUSER_PR_Callback
    struct {
        void *thunk;
        void *callback;
        void *args;
        void *ret;
        void *metadata;
    } callback;

    // LOREUSER_PR_PThreadCreate
    struct {
        void *thread;
        void *attr;
        void *start_routine;
        void *arg;
        int *ret;
    } pthread_create;

    // LOREUSER_PR_PThreadExit
    struct {
        void *ret;
    } pthread_exit;

    // LOREUSER_PR_HostLibraryOpen
    struct {
        const char *id;
    } host_library_open;
};

// =================================================================================

static uint64_t Lore_HandleMagicCall(int num, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    void **a = (void **) arg2;
    void *r = (void *) arg3;
    switch (arg1) {
        case LOREUSER_CT_CheckHealth: {
            printf("qemu (lorelei): check health\n");
            break;
        }
        case LOREUSER_CT_LoadLibrary: {
            const char *path = a[0];
            int flags = (int) (uintptr_t) a[1];
            void **ret_ref = r;
            *ret_ref = dlopen(path, flags);
            return 0;
        }
        case LOREUSER_CT_FreeLibrary: {
            void *handle = a[0];
            int *ret_ref = r;
            *ret_ref = dlclose(handle);
            return 0;
        }
        case LOREUSER_CT_GetProcAddress: {
            void *handle = a[0];
            const char *name = a[1];
            void **ret_ref = r;
            void *sym = dlsym(handle, name);
            if (!sym) {
                sym = dlsym(RTLD_DEFAULT, name);
            }
            *ret_ref = sym;
            return 0;
        }
        case LOREUSER_CT_GetErrorMessage: {
            char **ret_ref = r;
            *ret_ref = dlerror();
            return 0;
        }
        case LOREUSER_CT_GetModulePath: {
            void *addr = a[0];
            int is_handle = (int) (intptr_t) a[1];
            const char **ret_ref = r;
            if (is_handle) {
                struct link_map *lm;
                if (dlinfo(addr, RTLD_DI_LINKMAP, &lm) == 0) {
                    if (lm->l_name && lm->l_name[0] != '\0') {
                        *ret_ref = lm->l_name;
                    } else {
                        *ret_ref = NULL;
                    }
                } else {
                    *ret_ref = NULL;
                }
            } else {
                Dl_info info;
                if (dladdr(addr, &info) == 0) {
                    *ret_ref = NULL;
                } else {
                    *ret_ref = info.dli_fname;
                }
            }
            return 0;
        }
        case LOREUSER_CT_InvokeHostProc: {
            LoreThreadNextCall = (void *) r; // save
            int convention = (int) (intptr_t) a[0];
            switch (convention) {
                case LOREUSER_PC_Function: {
                    typedef void (*Func)(void *, void *, void *);
                    Func func = a[1];
                    void *args = a[2];
                    void *ret = a[3];
                    void *metadata = a[4];
                    func(args, ret, metadata);
                    break;
                }
                case LOREUSER_PC_ThreadEntry: {
                    typedef void *(*Func)(void *);
                    Func func = a[1];
                    void *args = a[2];
                    void **ret_ref = a[3];
                    *ret_ref = func(args);
                    break;
                }
                case LOREUSER_PC_HostCallback: {
                    typedef void (*Func)(void *, void *, void *, void *);
                    Func func = a[1];
                    void **newArgs = a[2];
                    void *ret = a[3];
                    void *metadata = a[4];
                    func(newArgs[0], newArgs[1], ret, metadata);
                    break;
                }
                default:
                    break;
            }
            return 0;
        }
        default: {
            if (LoreEmuContext.HandleExtraGuestCall) {
                LoreEmuContext.HandleExtraGuestCall(arg1, a, r);
            }
            break;
        }
    }
    return 0;
}

static inline void cpu_loop_shared(CPUX86State *env) {
    CPUState *cs = env_cpu(env);
    int trapnr;
    abi_ulong ret;

    for(;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        process_queued_cpu_work(cs);

        switch(trapnr) {
        case 0x80:
#ifndef TARGET_X86_64
        case EXCP_SYSCALL:
#endif
        {
            // ======================================================
            // Handle magic call
            if (env->regs[R_EAX] == LOREUSER_SYSCALL_NUM) {
                // `LOREUSER_CT_ResumeHostProc` means this cpu_loop is a temporary routine called by
                // host library, and it should return to the host library immediately.
                if (env->regs[R_EBX] == LOREUSER_CT_ResumeHostProc) {
                    process_pending_signals(env);
                    return;
                }
                ret = Lore_HandleMagicCall(
                                    env->regs[R_EAX],
                                    env->regs[R_EBX],
                                    env->regs[R_ECX],
                                    env->regs[R_EDX]);
                env->regs[R_EAX] = ret;
                break;
            }
            // ======================================================

            /* linux syscall from int $0x80 */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EBX],
                             env->regs[R_ECX],
                             env->regs[R_EDX],
                             env->regs[R_ESI],
                             env->regs[R_EDI],
                             env->regs[R_EBP],
                             0, 0);
            if (ret == -QEMU_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
        }
#ifdef TARGET_X86_64
        case EXCP_SYSCALL:
        {
            // ======================================================
            // Handle magic call
            if (env->regs[R_EAX] == LOREUSER_SYSCALL_NUM) {
                // `LOREUSER_CT_ResumeHostProc` means this cpu_loop is a temporary routine called by
                // host library, and it should return to the host library immediately.
                if (env->regs[R_EDI] == LOREUSER_CT_ResumeHostProc) {
                    process_pending_signals(env);
                    return;
                }
                ret = Lore_HandleMagicCall(
                                    env->regs[R_EAX],
                                    env->regs[R_EDI],
                                    env->regs[R_ESI],
                                    env->regs[R_EDX]);
                env->regs[R_EAX] = ret;
                break;
            }
            // ======================================================

            /* linux syscall from syscall instruction.  */
            ret = do_syscall(env,
                             env->regs[R_EAX],
                             env->regs[R_EDI],
                             env->regs[R_ESI],
                             env->regs[R_EDX],
                             env->regs[10],
                             env->regs[8],
                             env->regs[9],
                             0, 0);
            if (ret == -QEMU_ERESTARTSYS) {
                env->eip -= 2;
            } else if (ret != -QEMU_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
        }
        case EXCP_VSYSCALL:
            emulate_vsyscall(env);
            break;
#endif
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            force_sig(TARGET_SIGBUS);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
            if (maybe_handle_vm86_trap(env, trapnr)) {
                break;
            }
            force_sig(TARGET_SIGSEGV);
            break;
        case EXCP0E_PAGE:
            force_sig_fault(TARGET_SIGSEGV,
                            (env->error_code & PG_ERROR_P_MASK ?
                             TARGET_SEGV_ACCERR : TARGET_SEGV_MAPERR),
                            env->cr[2]);
            break;
        case EXCP00_DIVZ:
            if (maybe_handle_vm86_trap(env, trapnr)) {
                break;
            }
            force_sig_fault(TARGET_SIGFPE, TARGET_FPE_INTDIV, env->eip);
            break;
        case EXCP01_DB:
            if (maybe_handle_vm86_trap(env, trapnr)) {
                break;
            }
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->eip);
            break;
        case EXCP03_INT3:
            if (maybe_handle_vm86_trap(env, trapnr)) {
                break;
            }
            force_sig(TARGET_SIGTRAP);
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
            if (maybe_handle_vm86_trap(env, trapnr)) {
                break;
            }
            force_sig(TARGET_SIGSEGV);
            break;
        case EXCP06_ILLOP:
            force_sig_fault(TARGET_SIGILL, TARGET_ILL_ILLOPN, env->eip);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            force_sig_fault(TARGET_SIGTRAP, TARGET_TRAP_BRKPT, env->eip);
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            EXCP_DUMP(env, "qemu: unhandled CPU exception 0x%x - aborting\n",
                      trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}

// Host library may call these functions to interact with guest environment, the guest runtime
// should finally use `LOREUSER_CT_ResumeHostProc` to return to the host library.
static void Lore_EmuEntry_ExecuteCallback(void *thunk, void *callback, void *args, void *ret, void *metadata) {
    CPUState *cs = thread_cpu;
    CPUX86State *env = cpu_env(cs);

    env->regs[R_EAX] = LOREUSER_PR_Callback;

    __auto_type next_call = LoreThreadNextCall;
    next_call->callback.thunk = thunk;
    next_call->callback.callback = callback;
    next_call->callback.args = args;
    next_call->callback.ret = ret;
    next_call->callback.metadata = metadata;

    // Return to guest
    cpu_loop_shared(env);
}

static void Lore_EmuEntry_NotifyPThreadCreate(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg, int *ret) {
    CPUState *cs = thread_cpu;
    CPUX86State *env = cpu_env(cs);

    env->regs[R_EAX] = LOREUSER_PR_PThreadCreate;

    LoreHostThreadContext.LastThreadAttr = attr;

    __auto_type next_call = LoreThreadNextCall;
    next_call->pthread_create.thread = thread;
    next_call->pthread_create.attr = (void *) attr;
    next_call->pthread_create.start_routine = start_routine;
    next_call->pthread_create.arg = arg;
    next_call->pthread_create.ret = ret;

    // Return to guest
    cpu_loop_shared(env);
}

static void Lore_EmuEntry_NotifyPThreadExit(void *ret) {
    CPUState *cs = thread_cpu;
    CPUX86State *env = cpu_env(cs);

    env->regs[R_EAX] = LOREUSER_PR_PThreadExit;

    __auto_type next_call = LoreThreadNextCall;
    next_call->pthread_exit.ret = ret;

    // Return to guest
    cpu_loop_shared(env);
}

static pthread_t Lore_EmuEntry_GetLastPThreadId(void) {
    return LoreHostThreadContext.LastThreadId;
}

static void Lore_EmuEntry_NotifyHostLibraryOpen(const char *id) {
    CPUState *cs = thread_cpu;
    CPUX86State *env = cpu_env(cs);

    env->regs[R_EAX] = LOREUSER_PR_HostLibraryOpen;

    __auto_type next_call = LoreThreadNextCall;
    next_call->host_library_open.id = id;

    // Return to guest
    cpu_loop_shared(env);
}

void cpu_loop(CPUX86State *env)
{
    cpu_loop_shared(env);

    __builtin_unreachable();
}

void init_lorelei(void) {
    const char *root = getenv("LORELEI_ROOT");
    if (!root) {
        printf("qemu (lorelei): LORELEI_ROOT not defined.\n");
        return;
    }

    char host_runtime[PATH_MAX];
    (void) snprintf(host_runtime, PATH_MAX, "%s/lib/lorehrt.so", root);

    void *handle = dlopen(host_runtime, RTLD_NOW);
    if (!handle) {
        printf("qemu (lorelei): failed to open host runtime \"%s\".\n", host_runtime);
        return;
    }
    void *s1 = dlsym(handle, "Lore_HandleExtraGuestCall");
    if (!s1) {
        printf("nc: failed to get address of Lore_HandleExtraGuestCall\n");
        dlclose(handle);
        return;
    }
    void *s2 = dlsym(handle, "Lore_HrtGetEmuApis");
    if (!s2) {
        printf("nc: failed to get address of Lore_HrtGetEmuApis\n");
        dlclose(handle);
        return;
    }

    LoreEmuContext.LibraryHandle = handle;
    LoreEmuContext.HandleExtraGuestCall = s1;
    LoreEmuContext.HrtGetEmuApis = s2;

    struct LoreEmuApis *apis = LoreEmuContext.HrtGetEmuApis();
    apis->ExecuteCallback = Lore_EmuEntry_ExecuteCallback;
    apis->GetLastPThreadId = Lore_EmuEntry_GetLastPThreadId;
    apis->NotifyPThreadCreate = Lore_EmuEntry_NotifyPThreadCreate;
    apis->NotifyPThreadExit = Lore_EmuEntry_NotifyPThreadExit;
    apis->NotifyHostLibraryOpen = Lore_EmuEntry_NotifyHostLibraryOpen;
}

static void target_cpu_free(void *obj)
{
    CPUArchState *env = cpu_env(obj);
    target_munmap(env->gdt.base, sizeof(uint64_t) * TARGET_GDT_ENTRIES);
    g_free(obj);
}

void target_cpu_copy_regs(CPUArchState *env, struct target_pt_regs *regs)
{
    CPUState *cpu = env_cpu(env);
    bool is64 = (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) != 0;
    int i;

    OBJECT(cpu)->free = target_cpu_free;
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }

    /* enable 64 bit mode if possible */
    if (is64) {
        env->cr[4] |= CR4_PAE_MASK;
        env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
        env->hflags |= HF_LMA_MASK;
    }
#ifndef TARGET_ABI32
    else {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
#ifndef TARGET_ABI32
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_EBP] = regs->rbp;
    env->regs[R_ESP] = regs->rsp;
    env->eip = regs->rip;
#else
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
#endif

    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h_untagged(env->idt.base);
    for (i = 0; i < 20; i++) {
        set_idt(i, 0, is64);
    }
    set_idt(3, 3, is64);
    set_idt(4, 3, is64);
    set_idt(0x80, 3, is64);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ|PROT_WRITE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h_untagged(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
#ifdef TARGET_ABI32
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
    /* This hack makes Wine work... */
    env->segs[R_FS].selector = 0;
#else
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
#endif
}
