#include "wuwa_d0_mm_fault.h"

#include <linux/stddef.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>

#include "wuwa_common.h"
#include "wuwa_utils.h"

struct fault_probe_data {
    unsigned long far;
    unsigned long esr;
    struct pt_regs *regs;

    struct pt_regs old_regs;
    unsigned long thread_flags;
};

// void do_mem_abort(unsigned long far, unsigned long esr, struct pt_regs *regs)
static int do_mem_abort_entry(struct kretprobe_instance *ri,
                              struct pt_regs *regs)
{
#if CONFIG_REDIRECT_VIA_ABORT == 1
    struct fault_probe_data *d = (struct fault_probe_data *)ri->data;
    unsigned long far;
    unsigned long esr;
    struct pt_regs *user_regs;

    far = regs->regs[0];
    esr = regs->regs[1];
    user_regs = (typeof(user_regs))regs->regs[2];

    d->far = far;
    d->esr = esr;
    d->regs = user_regs;

    memcpy(&d->old_regs, user_regs, sizeof(*user_regs));

    d->thread_flags = current->thread_info.flags;
#endif
    return 0;
}

static int do_mem_abort_ret(struct kretprobe_instance *ri,
                            struct pt_regs *regs)
{
#if CONFIG_REDIRECT_VIA_ABORT == 1
    struct fault_probe_data *d = (struct fault_probe_data *)ri->data;
    unsigned long far = d->far;
    unsigned long esr = d->esr;
    struct pt_regs *user_regs = d->regs;

    if (far == LUCKY_LUO) {
        ovo_info("Lucky memory access at 0x%lx, esr=0x%lx\n", far, esr);
        ovo_info("pc=0x%llx, sp=0x%llx, fp=0x%llx\n",
                 user_regs->pc, user_regs->sp, user_regs->regs[29]);

        memcpy(user_regs, &d->old_regs, sizeof(*user_regs));

        u64 magic[2];
        u64 __user *sp = (typeof(sp))user_regs->sp;
        if (copy_from_user(&magic, sp, sizeof(magic)) == 0) {
            ovo_info("Magic values: 0x%llx, 0x%llx\n", magic[0], magic[1]);
        }

        if (magic[0] != LUCKY_LUO) {
            return 0; // Not a valid magic value, do nothing
        }

        if (system_supports_bti()) {
            user_regs->pstate &= ~PSR_BTYPE_MASK;
            user_regs->pstate |= PSR_BTYPE_C;
        }

        /* TCO (Tag Check Override) always cleared for signal handlers */
        user_regs->pstate &= ~PSR_TCO_BIT;

        user_regs->pc = magic[1];

        struct task_struct *tsk = current;

        spin_lock_irq(&tsk->sighand->siglock);

        sigdelset(&tsk->pending.signal, SIGSEGV);
        sigdelset(&tsk->signal->shared_pending.signal, SIGSEGV);

        static void (*recalc_sigpending)(void) = NULL;
        if (recalc_sigpending == NULL) {
            recalc_sigpending = (void (*)(void))kallsyms_lookup_name("recalc_sigpending");
        }

        recalc_sigpending();

        spin_unlock_irq(&tsk->sighand->siglock);
    }
#endif
    return 0;
}

// void arm64_force_sig_fault(int signo, int code, unsigned long far,const char *str)
static int arm64_force_sig_fault_pre(struct kprobe *p, struct pt_regs *regs) {
    return 0;
}

static void arm64_force_sig_fault_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
}

static struct kretprobe krp_do_mem_abort = {
    .kp.symbol_name = "do_mem_abort",
    .handler       = do_mem_abort_ret,
    .entry_handler = do_mem_abort_entry,
    .data_size     = sizeof(struct fault_probe_data),
    .maxactive     = 20,
};

static struct kprobe kp_arm64_force_sig_fault = {
    .symbol_name = "arm64_force_sig_fault",
    .pre_handler = arm64_force_sig_fault_pre,
    .post_handler = arm64_force_sig_fault_post,
};

int init_d0_mm_fault(void) {
    int ret, maxactive;

    maxactive = 2 * num_possible_cpus();
    if (maxactive < 20) {
        maxactive = 20;
    }

    krp_do_mem_abort.maxactive = maxactive;

    ret = register_kretprobe(&krp_do_mem_abort);
    if (ret < 0) {
        wuwa_err("register_kretprobe failed, returned %d\n", ret);
        goto out;
    }

    ret = register_kprobe(&kp_arm64_force_sig_fault);
    if (ret < 0) {
        wuwa_err("register_kprobe for arm64_force_sig_fault failed, returned %d\n", ret);
        unregister_kretprobe(&krp_do_mem_abort);
        goto out;
    }

    return 0;

    out:
    return ret;
}

void cleanup_d0_mm_fault(void) {
    unregister_kretprobe(&krp_do_mem_abort);
    unregister_kprobe(&kp_arm64_force_sig_fault);
}