#include "wuwa_safe_signal.h"
#include <asm/ucontext.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/signal_types.h>
#include <linux/stddef.h>
#include <linux/vmalloc.h>
#include "wuwa_common.h"
#include "wuwa_utils.h"

struct unsafe_region_area {
    u64 addr;
    u32 nums_page;
    uid_t uid;
    pid_t session_pid;
} __aligned(sizeof(u64));

static struct karray_list* unsafe_region_areas = NULL;
static DEFINE_RWLOCK(unsafe_region_areas_lock);

static bool is_safe_prof_signal(struct ksignal* ksig, struct pt_regs* regs) {
    u64 lr = regs->regs[30];
    u64 pc = regs->pc;

    if (!unsafe_region_areas->data) {
        wuwa_err("unsafe region areas list is empty\n");
        return true;
    }

    read_lock(&unsafe_region_areas_lock);

    for (int i = 0; i < unsafe_region_areas->size; ++i) {
        struct unsafe_region_area* area = unsafe_region_areas->data[i];
        if (!area) {
            continue;
        }
        if (area->uid != current_uid().val) {
            continue;
        }
        u64 start = area->addr;
        u64 end = start + area->nums_page * PAGE_SIZE;
        if (pc >= start && pc < end) {
            // The PC is within a safe region
            wuwa_info("PC=0x%llx is in a unsafe region for pid %d\n", pc, current->pid);
            read_unlock(&unsafe_region_areas_lock);
            return false;
        }

        if (lr >= start && lr < end) {
            // The LR is within a safe region
            wuwa_info("LR=0x%llx is in a unsafe region for pid %d\n", lr, current->pid);
            read_unlock(&unsafe_region_areas_lock);
            return false;
        }
    }

    read_unlock(&unsafe_region_areas_lock);

    return true;
}

struct setup_rt_frame_data {
    int unsafe;
    int usig;
    struct ksignal* ksig;
    sigset_t* set;
    struct pt_regs* regs;
    struct pt_regs old_regs;
};

/*
 * Do a signal return; undo the signal stack. These are aligned to 128-bit.
 */
struct rt_sigframe {
    struct siginfo info;
    struct ucontext uc;
};

struct user_access_state {
    u64 por_el0;
};

// static int setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set, struct pt_regs *regs)
// kernel 6.1 static int setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set, struct pt_regs *regs)
static int setup_rt_frame_entry(struct kretprobe_instance* ri, struct pt_regs* regs) {
    int usig = (int)regs->regs[0];
    struct ksignal* ksig = (struct ksignal*)regs->regs[1];
    sigset_t* set = (sigset_t*)regs->regs[2];
    struct pt_regs* user_regs = (struct pt_regs*)regs->regs[3];

    struct setup_rt_frame_data* d = (struct setup_rt_frame_data*)ri->data;
    d->unsafe = 0;
    d->usig = usig;
    d->ksig = ksig;
    d->set = set;
    d->regs = user_regs;

    if (usig < 0 || usig >= _NSIG) {
        wuwa_err("Invalid signal number: %d\n", usig);
        return 0;
    }
    if (!ksig || !set) {
        wuwa_err("Invalid ksignal or sigset_t pointer\n");
        return 0;
    }

    if (usig == SIGPROF && !is_safe_prof_signal(ksig, user_regs)) {
        d->unsafe = 1;
        regs_set_return_value(regs, 1);
        regs->pc = regs->regs[30];
        return 1;
    }

#if CONFIG_REDIRECT_VIA_SIGNAL != 0
    if (usig == SIGSEGV && (u64)ksig->info.si_addr == LUCKY_LUO) {
        wuwa_info("==> setup_rt_frame_entry: Lucky SIGSEGV caught, pid=%d\n", current->pid);
        wuwa_info("    x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx\n", user_regs->regs[0], user_regs->regs[1],
                  user_regs->regs[2], user_regs->regs[3]);
        wuwa_info("    pc=0x%llx, lr=0x%llx, sp=0x%llx, fp=0x%llx\n", user_regs->pc, user_regs->regs[30], user_regs->sp,
                  user_regs->regs[29]);

        // static void(*fpsimd_signal_save_current_state)(void) = NULL;
        // if (!fpsimd_signal_save_current_state) {
        //     fpsimd_signal_save_current_state =
        //     (void(*)(void))kallsyms_lookup_name_ex("fpsimd_signal_preserve_current_state");
        //     ovo_info("fpsimd_signal_preserve_current_state found at %p\n", fpsimd_signal_save_current_state);
        // }
        // if (!fpsimd_signal_save_current_state) {
        //     fpsimd_signal_save_current_state =
        //     (void(*)(void))kallsyms_lookup_name_ex("fpsimd_save_and_flush_current_state");
        //     ovo_info("fpsimd_save_and_flush_current_state found at %p\n", fpsimd_signal_save_current_state);
        // }
        // if (fpsimd_signal_save_current_state) {
        //     fpsimd_signal_save_current_state();
        // } else {
        //     ovo_err("fpsimd_signal_save_current_state not found, cannot preserve FPSIMD state\n");
        //     return 0;
        // }

        memcpy(&d->old_regs, user_regs, sizeof(d->old_regs));
    }
#endif

    return 0;
}

static int setup_rt_frame_ret(struct kretprobe_instance* ri, struct pt_regs* regs) {
    struct setup_rt_frame_data* d = (struct setup_rt_frame_data*)ri->data;
    if (unlikely(!d))
        return 0;

    int usig = d->usig;
    struct ksignal* ksig = d->ksig;
    sigset_t* set = d->set;
    struct pt_regs* user_regs = d->regs;

    if (d->unsafe) {
        wuwa_warn("Unsafe SIGPROF detected, usig=%d\n", usig);
        return 0;
    }

    if (usig < 0 || usig >= _NSIG || !ksig || !set || !user_regs)
        return 0;

#if CONFIG_REDIRECT_VIA_SIGNAL != 0
    if (usig == SIGSEGV && (u64)ksig->info.si_addr == LUCKY_LUO) {
        if (ksig->ka.sa.sa_handler != (void __user*)LUCKY_LUO) {
            wuwa_warn("setup_rt_frame_ret: Lucky SIGSEGV caught, but handler is not set to LUCKY_LUO\n");
        }

        int handler_usig = user_regs->regs[0];
        u64 handler_info = user_regs->regs[1];
        u64 hanlder_uc = user_regs->regs[2];
        u64 sp = user_regs->sp;
        u64 fp = user_regs->regs[29];
        u64 lr_sigtramp = user_regs->regs[30];
        u64 pc_handler = user_regs->pc;

        wuwa_info("setup_rt_frame_ret: Lucky SIGSEGV caught!\n");
        wuwa_info("setup_rt_frame_ret: usig=%d, handler_info=0x%llx, hanlder_uc=0x%llx, sp=0x%llx, fp=0x%llx, "
                  "lr_sigtramp=0x%llx, pc_handler=0x%llx\n",
                  handler_usig, handler_info, hanlder_uc, sp, fp, lr_sigtramp, pc_handler);

        struct k_sigaction* ka;
        ka = &current->sighand->action[usig - 1];
        if (ka->sa.sa_handler == SIG_IGN || ka->sa.sa_handler == SIG_DFL) {
            ka->sa.sa_handler = (__sighandler_t)LUCKY_LUO;
        }

        if (!(ksig->ka.sa.sa_flags & SA_NODEFER)) {
            ksig->ka.sa.sa_flags |= SA_NODEFER;
        }

#if defined(CONFIG_ARM64_SME)
#error "SME not supported in this module"
        if (system_supports_sme()) {
            current->thread.svcr &= ~SVCR_ZA_MASK;
            write_sysreg_s(0, SYS_TPIDR2_EL0);
        }
#endif

        struct pt_regs sig_regs;
        memcpy(&sig_regs, user_regs, sizeof(sig_regs));
        memcpy(user_regs, &d->old_regs, sizeof(d->old_regs));

        d->unsafe = 1;
        if (system_supports_bti()) {
            user_regs->pstate &= ~PSR_BTYPE_MASK;
            user_regs->pstate |= PSR_BTYPE_C;
        }

        /* TCO (Tag Check Override) always cleared for signal handlers */
        user_regs->pstate &= ~PSR_TCO_BIT;

        u64 magic[2];
        u64 __user* magic_sp = (typeof(magic_sp))user_regs->sp;
        if (copy_from_user(&magic, magic_sp, sizeof(magic)) == 0) {
            ovo_info("Magic values: 0x%llx, 0x%llx\n", magic[0], magic[1]);
        }

        if (magic[0] != LUCKY_LUO) {
            return 0; // Not a lucky luo signal
        }

        user_regs->pc = magic[1];
        ksig->ka.sa.sa_handler = (__sighandler_t)user_regs->pc;

        // sigset_t blocked;
        // clear_restore_sigmask();
        // sigorsets(&blocked, &current->blocked, &ksig->ka.sa.sa_mask);
        // sigdelset(&blocked, ksig->sig);
        // static void (*set_current_blocked)(sigset_t *) = NULL;
        // if (!set_current_blocked) {
        //     set_current_blocked = (typeof(set_current_blocked))kallsyms_lookup_name_ex("set_current_blocked");
        // }
        // if (set_current_blocked)
        //     set_current_blocked(&blocked);
        //
        // spin_lock_irq(&current->sighand->siglock);
        //
        // sigdelset(&current->pending.signal, ksig->sig);
        // sigdelset(&current->signal->shared_pending.signal, ksig->sig);
        // static void (*recalc_sigpending)(void) = NULL;
        // if (recalc_sigpending == NULL) {
        //     recalc_sigpending = (typeof(recalc_sigpending))kallsyms_lookup_name_ex("recalc_sigpending");
        // }
        // recalc_sigpending();
        //
        // spin_unlock_irq(&current->sighand->siglock);

        static int (*valid_user_regs)(struct user_pt_regs* regs, struct task_struct* task) = NULL;
        if (valid_user_regs == NULL) {
            valid_user_regs = (typeof(valid_user_regs))kallsyms_lookup_name_ex("valid_user_regs");
        }

        ovo_info("Lucky SIGSEGV setup complete, pc=0x%llx, lr=0x%llx, invalid: %d\n", user_regs->pc,
                 user_regs->regs[30], !valid_user_regs(&user_regs->user_regs, current));

        regs_set_return_value(regs, 0);
    }
#endif

    return 0;
}


struct rp_data_get_signal {
    struct ksignal* ksig_ptr; /* get_signal()'s first argument */
};

// bool get_signal(struct ksignal *ksig)
static int get_signal_entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    struct rp_data_get_signal* data = (struct rp_data_get_signal*)ri->data;
    struct ksignal* ksig;

    ksig = (struct ksignal*)regs->regs[0];
    data->ksig_ptr = ksig;

    // if (ksig->sig != SIGSEGV)
    //     return 0;
    //
    // if (ksig->info.si_addr != (void *)LUCKY_LUO)
    //     return 0;
    //
    // ksig->ka.sa.sa_handler = (__sighandler_t)LUCKY_LUO;
    // ksig->ka.sa.sa_flags  &= ~SA_RESETHAND;
    // ksig->ka.sa.sa_flags  |= SA_NODEFER;
    //
    // sigdelset(&ksig->ka.sa.sa_mask, ksig->sig);

    return 0;
}

static int get_signal_ret_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
    struct rp_data_get_signal* data;
    struct ksignal* ksig;
    unsigned long retval;

    if (!ri || !regs)
        return 0;

    data = (struct rp_data_get_signal*)ri->data;
    if (unlikely(!data || !data->ksig_ptr))
        return 0;

    ksig = data->ksig_ptr;
    retval = regs_return_value(regs);

#if CONFIG_REDIRECT_VIA_SIGNAL != 0
    if (ksig->info.si_signo == SIGSEGV && ksig->info.si_addr == (void*)LUCKY_LUO) {
        ksig->ka.sa.sa_handler = (void __user*)LUCKY_LUO;
        wuwa_info("====> get_signal_ret_handler: Lucky SIGSEGV caught, setting handler to LUCKY_LUO\n");

        if (!(ksig->ka.sa.sa_flags & SA_SIGINFO)) {
            ksig->ka.sa.sa_flags |= SA_SIGINFO;
            wuwa_info("get_signal_ret_handler: Setting SA_SIGINFO flag for Lucky SIGSEGV\n");
        }

        if (!retval)
            regs_set_return_value(regs, 1);
    }
#endif

    return 0;
}

static struct kretprobe krp_setup_rt_frame = {
    .kp.symbol_name = "setup_rt_frame",
    .entry_handler = setup_rt_frame_entry,
    .handler = setup_rt_frame_ret,
    .data_size = sizeof(struct setup_rt_frame_data),
    .maxactive = 20,
};

static struct kretprobe krpget_signal = {
    .kp.symbol_name = "get_signal",
    .entry_handler = get_signal_entry_handler,
    .handler = get_signal_ret_handler,
    .data_size = sizeof(struct rp_data_get_signal),
    .maxactive = 20,
};

int wuwa_safe_signal_init(void) {
    int ret, maxactive;

    maxactive = num_possible_cpus() * 2;
    if (maxactive < 20) {
        maxactive = 20; // Ensure a minimum number of active probes
    }
    krp_setup_rt_frame.maxactive = maxactive;
    krpget_signal.maxactive = maxactive;


    ret = register_kretprobe(&krp_setup_rt_frame);
    if (ret) {
        wuwa_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    ret = register_kretprobe(&krpget_signal);
    if (ret) {
        wuwa_err("register_kretprobe failed, returned %d\n", ret);
        goto out;
    }

    unsafe_region_areas = arraylist_create(ARRAYLIST_DEFAULT_CAPACITY);
    if (!unsafe_region_areas) {
        wuwa_err("failed to create unsafe region areas list\n");
        ret = -ENOMEM;
        goto out_krpget_signal;
    }

    return 0;

out_krpget_signal:
    unregister_kretprobe(&krpget_signal);
out:
    unregister_kretprobe(&krp_setup_rt_frame);
    return ret;
}

void wuwa_safe_signal_cleanup(void) {
    unregister_kretprobe(&krp_setup_rt_frame);
    unregister_kretprobe(&krpget_signal);

    write_lock(&unsafe_region_areas_lock);
    if (unsafe_region_areas) {
        if (!unsafe_region_areas->data) {
            write_unlock(&unsafe_region_areas_lock);
            wuwa_err("unsafe region areas list is empty\n");
            goto next;
        }

        for (int i = 0; i < unsafe_region_areas->size; ++i) {
            void* element = unsafe_region_areas->data[i];
            if (element)
                kvfree(element);
        }

    next:
        arraylist_destroy(unsafe_region_areas);
        unsafe_region_areas = NULL;
    }
    write_unlock(&unsafe_region_areas_lock);
}

int wuwa_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page) {
    write_lock(&unsafe_region_areas_lock);

    if (!unsafe_region_areas) {
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }

    struct unsafe_region_area* area = kvzalloc(sizeof(*area), GFP_KERNEL);
    if (!area) {
        wuwa_err("failed to allocate memory for unsafe region area\n");
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }
    area->addr = start;
    area->nums_page = num_page;
    area->uid = uid;
    area->session_pid = session;

    if (arraylist_add(unsafe_region_areas, area)) {
        write_unlock(&unsafe_region_areas_lock);
        wuwa_err("failed to add unsafe region area\n");
        return -ENOMEM;
    }

    wuwa_info("unsafe region area added for pid %d, start=0x%lx, num_page=%zu\n", session, start, num_page);
    write_unlock(&unsafe_region_areas_lock);
    return 0;
}

int wuwa_del_unsafe_region(pid_t pid) {
    write_lock(&unsafe_region_areas_lock);

    if (!unsafe_region_areas) {
        write_unlock(&unsafe_region_areas_lock);
        return -ENOMEM;
    }

    if (!unsafe_region_areas->data) {
        write_unlock(&unsafe_region_areas_lock);
        wuwa_err("unsafe region areas list is empty\n");
        return -ENOENT;
    }

    for (int i = 0; i < unsafe_region_areas->size; ++i) {
        struct unsafe_region_area* area = unsafe_region_areas->data[i];
        if (area && area->session_pid == pid) {
            void* removed = arraylist_remove(unsafe_region_areas, i);
            if (removed) {
                kvfree(removed);
            } else {
                wuwa_err("failed to remove unsafe region area for pid %d\n", pid);
            }
        }
    }

    write_unlock(&unsafe_region_areas_lock);
    return 0;
}
