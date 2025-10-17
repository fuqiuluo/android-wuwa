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

    return 0;
}

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
    krpget_signal.maxactive = maxactive;

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
    return ret;
}

void wuwa_safe_signal_cleanup(void) {
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
