#include <stdint.h>
#include <stddef.h>
#include <sys/sched.h>
#include <mm/mm.h>
#include <lib/klib.h>
#include <sys/panic.h>
#include <sys/smp.h>
#include <lib/lock.h>
#include <acpi/madt.h>
#include <sys/apic.h>
#include <sys/ipi.h>
#include <lib/time.h>
#include <lib/event.h>
#include <sys/pit.h>

#define SCHED_TIMESLICE_MS 5

static int scheduler_ready = 0;

void task_spinup(void *, size_t);

lock_t scheduler_lock = new_lock_acquired;
lock_t resched_lock = new_lock;

struct process_t **process_table;

struct thread_t **task_table;
int64_t task_count = 0;

/* These represent the default new-thread register contexts for kernel space and
 * userspace. See kernel/include/ctx.h for the register order. */
static struct regs_t default_krnl_regs = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x08,0x202,0,0x10};
static struct regs_t default_usr_regs = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x23,0x202,0,0x1b};

static uint8_t default_fxstate[512] __attribute__((aligned(16)));

void init_sched(void) {
    fxsave(&default_fxstate);

    kprint(KPRN_INFO, "sched: Initialising process table...");

    /* Make room for task table */
    if ((task_table = kalloc(MAX_TASKS * sizeof(struct thread_t *))) == 0) {
        panic("sched: Unable to allocate task table.", 0, 0, NULL);
    }
    if ((process_table = kalloc(MAX_PROCESSES * sizeof(struct process_t *))) == 0) {
        panic("sched: Unable to allocate process table.", 0, 0, NULL);
    }
    /* Now make space for PID 0 */
    kprint(KPRN_INFO, "sched: Creating PID 0");
    if ((process_table[0] = kalloc(sizeof(struct process_t))) == 0) {
        panic("sched: Unable to allocate space for kernel task", 0, 0, NULL);
    }
    if ((process_table[0]->threads = kalloc(MAX_THREADS * sizeof(struct thread_t *))) == 0) {
        panic("sched: Unable to allocate space for kernel threads.", 0, 0, NULL);
    }
    process_table[0]->pagemap = kernel_pagemap;
    process_table[0]->pid = 0;

    kprint(KPRN_INFO, "sched: Init done.");

    scheduler_ready = 1;

    return;
}

void yield(void) {
    spinlock_acquire(&scheduler_lock);
    force_resched();
}

void relaxed_sleep(uint64_t ms) {
    spinlock_acquire(&scheduler_lock);

    uint64_t yield_target = (uptime_raw + (ms * (PIT_FREQUENCY / 1000))) + 1;

    tid_t current_task = cpu_locals[current_cpu].current_task;
    task_table[current_task]->yield_target = yield_target;

    force_resched();
}

int task_send_child_event(pid_t pid, struct child_event_t *child_event) {
    spinlock_acquire(&scheduler_lock);
    struct process_t *process = process_table[pid];
    spinlock_release(&scheduler_lock);

    spinlock_acquire(&process->child_event_lock);

    process->child_event_i++;
    process->child_events = krealloc(process->child_events,
        sizeof(struct child_event_t) * process->child_event_i);

    process->child_events[process->child_event_i - 1] = *child_event;

    spinlock_release(&process->child_event_lock);
    event_trigger(&process->child_event);
    return 0;
}

/* Search for a new task to run */
static inline tid_t task_get_next(tid_t current_task) {
    if (current_task != -1) {
        current_task++;
    } else {
        current_task = 0;
    }

    for (int64_t i = 0; i < task_count; ) {
        struct thread_t *thread = task_table[current_task];
        if (!thread) {
            /* End of task table, rewind */
            current_task = 0;
            thread = task_table[current_task];
        }
        if (thread == (void *)(-1) || thread == (void *)(-2)) {
            /* This is an empty thread, skip */
            goto skip;
        }
        if (thread->yield_target > uptime_raw) {
            goto next;
        }
        if (!spinlock_test_and_acquire(&thread->lock)) {
            /* If unable to acquire the thread's lock, skip */
            goto next;
        }
        if (locked_read(int, &thread->paused)) {
            spinlock_release(&thread->lock);
            goto next;
        }
        if (thread->event_ptr) {
            if (!thread->event_abrt) {
                if (locked_read(event_t, thread->event_ptr)) {
                    locked_dec(thread->event_ptr);
                    thread->event_ptr = 0;
                } else {
                    spinlock_release(&thread->lock);
                    goto next;
                }
            }
        }
        return current_task;
        next:
        i++;
        skip:
        if (++current_task == MAX_TASKS)
            current_task = 0;
    }

    return -1;
}

__attribute__((noinline)) static void _idle(void) {
    int _current_cpu = current_cpu;
    cpu_locals[_current_cpu].current_task = -1;
    cpu_locals[_current_cpu].current_thread = -1;
    cpu_locals[_current_cpu].current_process = -1;
    spinlock_release(&scheduler_lock);
    spinlock_release(&resched_lock);
    asm volatile (
        "sti;"
        "1: "
        "hlt;"
        "jmp 1b;"
    );
}

__attribute__((noinline)) static void idle(void) {
    /* This idle function swaps cr3 and rsp then calls _idle for technical reasons */
    asm volatile (
        "mov rbx, cr3;"
        "cmp rax, rbx;"
        "je 1f;"
        "mov cr3, rax;"
        "1: "
        "mov rsp, qword ptr gs:[8];"
        "jmp _idle;"
        :
        : "a" ((size_t)kernel_pagemap->pml4 - MEM_PHYS_OFFSET)
    );
    /* Dead call so GCC doesn't garbage collect _idle */
    _idle();
}

void task_resched(struct regs_t *regs) {
    spinlock_acquire(&resched_lock);

    if (!spinlock_test_and_acquire(&scheduler_lock)) {
        spinlock_release(&resched_lock);
        return;
    }

    int _current_cpu = current_cpu;

    pid_t current_task = cpu_locals[_current_cpu].current_task;
    pid_t current_process = cpu_locals[_current_cpu].current_process;
    pid_t last_task = current_task;

    if (current_task != -1) {
        struct thread_t *current_thread = task_table[current_task];
        /* Save current context */
        current_thread->active_on_cpu = -1;
        current_thread->ctx.regs = *regs;
        if (current_process) {
            /* Save FPU context */
            fxsave(&current_thread->ctx.fxstate);
            /* Save user rsp */
            current_thread->ustack = cpu_locals[current_cpu].thread_ustack;
            /* Save errno */
            current_thread->thread_errno = cpu_locals[current_cpu].thread_errno;
        }
        /* Release lock on this thread */
        spinlock_release(&current_thread->lock);
    }

    /* Get to the next task */
    current_task = task_get_next(current_task);
    /* If there's nothing to do, idle */
    if (current_task == -1)
        idle();

    struct cpu_local_t *cpu_local = &cpu_locals[_current_cpu];
    struct thread_t *thread = task_table[current_task];

    cpu_local->current_task = current_task;
    cpu_local->current_thread = thread->tid;
    cpu_local->current_process = thread->process;

    if (thread->process) {
       cpu_local->thread_kstack = thread->kstack;
       cpu_local->thread_ustack = thread->ustack;
       cpu_local->thread_errno = thread->thread_errno;
       /* Restore FPU context */
       fxrstor(&thread->ctx.fxstate);
       /* Restore thread FS base */
       load_fs_base(thread->fs_base);
    }

    thread->active_on_cpu = _current_cpu;

    /* Swap cr3, if necessary */
    if (task_table[last_task]->process != thread->process) {
        /* Switch cr3 and return to the thread */
        task_spinup(&thread->ctx.regs, (size_t)process_table[thread->process]->pagemap->pml4 - MEM_PHYS_OFFSET);
    } else {
        /* Don't switch cr3 and return to the thread */
        task_spinup(&thread->ctx.regs, 0);
    }
}

static int pit_ticks = 0;

void task_resched_bsp(struct regs_t *regs) {
    if (scheduler_ready) {
        if (++pit_ticks == SCHED_TIMESLICE_MS) {
            pit_ticks = 0;
        } else {
            return;
        }

        for (int i = 1; i < smp_cpu_count; i++)
            lapic_send_ipi(i, IPI_RESCHED);

        /* Call task_scheduler on the BSP */
        task_resched(regs);
    }
}

void task_resched_ap(struct regs_t *regs) {
    locked_write(int, &cpu_locals[current_cpu].ipi_resched_received, 1);
    task_resched(regs);
}

#define BASE_BRK_LOCATION ((size_t)0x0000780000000000)

#define EMPTY ((void *)(size_t)-1)

/* Create process */
/* Returns process ID, -1 on failure */
pid_t task_pcreate(void) {
    spinlock_acquire(&scheduler_lock);

    /* Search for free process ID */
    pid_t new_pid;
    for (new_pid = 0; new_pid < MAX_PROCESSES - 1; new_pid++) {
        if (!process_table[new_pid] || process_table[new_pid] == (void *)(-1))
            goto found_new_pid;
    }
    spinlock_release(&scheduler_lock);
    return -1;

found_new_pid:
    process_table[new_pid] = (void *)(-2); // placeholder
    spinlock_release(&scheduler_lock);

    /* Try to make space for this new task */
    struct process_t *new_process = kalloc(sizeof(struct process_t));
    if (!new_process) {
        spinlock_acquire(&scheduler_lock);
        process_table[new_pid] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    if ((new_process->threads = kalloc(MAX_THREADS * sizeof(struct thread_t *))) == 0) {
        kfree(new_process);
        spinlock_acquire(&scheduler_lock);
        process_table[new_pid] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    if ((new_process->file_handles = kalloc(MAX_FILE_HANDLES * sizeof(int))) == 0) {
        kfree(new_process->threads);
        kfree(new_process);
        spinlock_acquire(&scheduler_lock);
        process_table[new_pid] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    /* Initially, mark all file handles as unused */
    for (size_t i = 0; i < MAX_FILE_HANDLES; i++) {
        new_process->file_handles[i] = -1;
    }

    new_process->file_handles_lock = new_lock;

    strcpy(new_process->cwd, "/");
    new_process->cwd_lock = new_lock;

    new_process->cur_brk = BASE_BRK_LOCATION;
    new_process->cur_brk_lock = new_lock;

    new_process->child_event_lock = new_lock;

    /* Create a new pagemap for the process */
    new_process->pagemap = new_address_space();
    if (!new_process->pagemap) {
        kfree(new_process->file_handles);
        kfree(new_process->threads);
        kfree(new_process);
        spinlock_acquire(&scheduler_lock);
        process_table[new_pid] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    new_process->pid = new_pid;

    // Actually "enable" the new process
    spinlock_acquire(&scheduler_lock);
    process_table[new_pid] = new_process;
    spinlock_release(&scheduler_lock);
    return new_pid;
}

void abort_thread_exec(size_t scheduler_not_locked) {
    load_cr3((size_t)kernel_pagemap->pml4 - MEM_PHYS_OFFSET);

    int _current_cpu = current_cpu;

    cpu_locals[_current_cpu].current_task = -1;
    cpu_locals[_current_cpu].current_thread = -1;
    cpu_locals[_current_cpu].current_process = -1;

    if (scheduler_not_locked) {
        locked_write(int, &cpu_locals[_current_cpu].ipi_abortexec_received, 1);
        lapic_eoi();
    }

    kprint(0, "aborting thread execution on CPU #%d", current_cpu);

    if (!scheduler_not_locked)
        force_resched();
    else
        yield();
}

#define STACK_LOCATION_TOP ((size_t)0x0000800000000000)
#define STACK_SIZE ((size_t)32768)

int task_tpause(pid_t pid, tid_t tid) {
    spinlock_acquire(&scheduler_lock);

    if (!process_table[pid]->threads[tid]
        || process_table[pid]->threads[tid] == (void *)(-1)
        || process_table[pid]->threads[tid] == (void *)(-2)) {
        spinlock_release(&scheduler_lock);
        return -1;
    }

    struct thread_t *thread = process_table[pid]->threads[tid];
    int active_on_cpu = thread->active_on_cpu;

    locked_write(int, &thread->event_abrt, 1);

    while (locked_read(int, &thread->in_syscall)) {
        force_resched();
        spinlock_acquire(&scheduler_lock);
    }

    locked_write(int, &thread->paused, 1);

    panic_unless(active_on_cpu != current_cpu);

    if (active_on_cpu != -1 && active_on_cpu != current_cpu) {
        locked_write(int, &cpu_locals[active_on_cpu].ipi_resched_received, 0);
        lapic_send_ipi(active_on_cpu, IPI_RESCHED);
        while (!locked_read(int, &cpu_locals[active_on_cpu].ipi_resched_received));
    }

    spinlock_release(&scheduler_lock);

    return 0;
}

int task_tresume(pid_t pid, tid_t tid) {
    spinlock_acquire(&scheduler_lock);

    if (!process_table[pid]->threads[tid]
        || process_table[pid]->threads[tid] == (void *)(-1)
        || process_table[pid]->threads[tid] == (void *)(-2)) {
        spinlock_release(&scheduler_lock);
        return -1;
    }

    locked_write(int, &process_table[pid]->threads[tid]->event_abrt, 0);
    locked_write(int, &process_table[pid]->threads[tid]->paused, 0);

    spinlock_release(&scheduler_lock);

    return 0;
}

/* Kill a thread in a given process */
/* Return -1 on failure */
int task_tkill(pid_t pid, tid_t tid) {
    spinlock_acquire(&scheduler_lock);

    if (!process_table[pid]->threads[tid]
        || process_table[pid]->threads[tid] == (void *)(-1)
        || process_table[pid]->threads[tid] == (void *)(-2)) {
        spinlock_release(&scheduler_lock);
        return -1;
    }

    struct thread_t *thread = process_table[pid]->threads[tid];
    int active_on_cpu = thread->active_on_cpu;

    locked_write(int, &thread->event_abrt, 1);

    while (locked_read(int, &thread->in_syscall)) {
        force_resched();
        spinlock_acquire(&scheduler_lock);
    }

    if (active_on_cpu != -1 && active_on_cpu != current_cpu) {
        /* Send abort execution IPI */
        locked_write(int, &cpu_locals[active_on_cpu].ipi_abortexec_received, 0);
        lapic_send_ipi(active_on_cpu, IPI_ABORTEXEC);
        while (!locked_read(int, &cpu_locals[active_on_cpu].ipi_abortexec_received));
    }

    task_table[process_table[pid]->threads[tid]->task_id] = (void *)(-1);

    void *kstack = (void *)(process_table[pid]->threads[tid]->kstack - STACK_SIZE);

    kfree(process_table[pid]->threads[tid]);

    process_table[pid]->threads[tid] = (void *)(-1);

    task_count--;

    if (active_on_cpu == current_cpu) {
        asm volatile (
            "mov rsp, qword ptr gs:[8];"
            "call kfree;"
            "cli;"
            "mov rdi, 0;"
            "call abort_thread_exec;"
            :
            : "D" (kstack)
        );
    } else {
        kfree(kstack);
    }

    spinlock_release(&scheduler_lock);

    return 0;
}

/* Create thread from function pointer */
/* Returns thread ID, -1 on failure */
tid_t task_tcreate(pid_t pid, enum tcreate_abi abi, const void *opaque_data) {
    spinlock_acquire(&scheduler_lock);

    /* Search for free thread ID in the process */
    tid_t new_tid;
    for (new_tid = 0; new_tid < MAX_THREADS; new_tid++) {
        if (!process_table[pid]->threads[new_tid] || process_table[pid]->threads[new_tid] == (void *)(-1))
            goto found_new_tid;
    }
    spinlock_release(&scheduler_lock);
    return -1;
found_new_tid:;
    process_table[pid]->threads[new_tid] = (void *)(-2); // placeholder

    /* Search for free global task ID */
    tid_t new_task_id;
    for (new_task_id = 0; new_task_id < MAX_TASKS; new_task_id++) {
        if (!task_table[new_task_id] || task_table[new_task_id] == (void *)(-1))
            goto found_new_task_id;
    }
    process_table[pid]->threads[new_tid] = EMPTY;
    spinlock_release(&scheduler_lock);
    return -1;
found_new_task_id:;
    task_table[new_task_id] = (void *)(-2); // placeholder

    spinlock_release(&scheduler_lock);

    /* Try to make space for this new thread */
    struct thread_t *new_thread;
    if (!(new_thread = kalloc(sizeof(struct thread_t)))) {
        spinlock_acquire(&scheduler_lock);
        process_table[pid]->threads[new_tid] = EMPTY;
        task_table[new_task_id] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    /* Set up a kernel stack for the thread */
    new_thread->kstack = (size_t)kalloc(STACK_SIZE) + STACK_SIZE;
    if (new_thread->kstack == STACK_SIZE) {
        kfree(new_thread);
        spinlock_acquire(&scheduler_lock);
        process_table[pid]->threads[new_tid] = EMPTY;
        task_table[new_task_id] = EMPTY;
        spinlock_release(&scheduler_lock);
        return -1;
    }

    new_thread->active_on_cpu = -1;

    /* Set registers to defaults */
    if (pid)
        new_thread->ctx.regs = default_usr_regs;
    else
        new_thread->ctx.regs = default_krnl_regs;

    /* Set up a user stack for the thread */
    if (pid) {
        /* Virtual addresses of the stack. */
        size_t stack_guardpage = STACK_LOCATION_TOP -
                                 (STACK_SIZE + PAGE_SIZE/*guard page*/) * (new_tid + 1);
        size_t stack_bottom = stack_guardpage + PAGE_SIZE;

        /* Allocate physical memory for the stack and initialize it. */
        char *stack_pm = pmm_allocz(STACK_SIZE / PAGE_SIZE);
        if (!stack_pm) {
            kfree((void *)(new_thread->kstack - STACK_SIZE));
            kfree(new_thread);
            spinlock_acquire(&scheduler_lock);
            process_table[pid]->threads[new_tid] = EMPTY;
            task_table[new_task_id] = EMPTY;
            spinlock_release(&scheduler_lock);
            return -1;
        }

        size_t *sbase = (size_t *)(stack_pm + STACK_SIZE + MEM_PHYS_OFFSET);
        panic_unless(!((size_t)sbase & 0xF) && "Stack base must be 16-byte aligned");

        size_t *sp;
        if (abi == tcreate_elf_exec) {
        }else{
            /* Do not push anything onto the stack. */
            sp = sbase;
        }
        panic_unless(!((size_t)sp & 0xF) && "Stack must be 16-byte aligned on x86_64");

        /* Map the stack */
        for (size_t i = 0; i < STACK_SIZE / PAGE_SIZE; i++) {
            map_page(process_table[pid]->pagemap,
                     (size_t)(stack_pm + (i * PAGE_SIZE)),
                     (size_t)(stack_bottom + (i * PAGE_SIZE)),
                     pid ? 0x07 : 0x03);
        }
        /* Add a guard page */
        unmap_page(process_table[pid]->pagemap, stack_guardpage);
        new_thread->ctx.regs.rsp = stack_bottom + STACK_SIZE - ((sbase - sp) * sizeof(size_t));
    } else {
        /* If it's a kernel thread, kstack is the main stack */
        new_thread->ctx.regs.rsp = new_thread->kstack;
    }

    /* Set instruction pointer to entry point */
    if (abi == tcreate_fn_call) {
        const struct tcreate_fn_call_data *data = opaque_data;
        new_thread->ctx.regs.rip = (size_t)data->fn;
        new_thread->ctx.regs.rdi = (size_t)data->arg;
        new_thread->fs_base = (size_t)data->fsbase;
    } else {
        panic_unless(abi == tcreate_elf_exec);
        const struct tcreate_elf_exec_data *data = opaque_data;
        new_thread->ctx.regs.rip = (size_t)data->entry;
    }

    memcpy(new_thread->ctx.fxstate, default_fxstate, 512);

    new_thread->tid = new_tid;
    new_thread->task_id = new_task_id;
    new_thread->process = pid;
    spinlock_release(&new_thread->lock);

    /* Actually "enable" the new thread */
    spinlock_acquire(&scheduler_lock);
    process_table[pid]->threads[new_tid] = new_thread;
    task_table[new_task_id] = new_thread;
    task_count++;
    spinlock_release(&scheduler_lock);
    return new_tid;
}

int exec(pid_t pid, const char *filename, const char *argv[], const char *envp[]) {
/*
    int ret;
    size_t entry;

    struct process_t *process = process_table[pid];

    struct pagemap_t *old_pagemap = process->pagemap;

    // Load the executable
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    // Check for a shebang
    char shebang[2];
    read(fd, shebang, 2);
    if (!strncmp(shebang, "#!", 2)) {
        return parse_shebang(fd, pid, argv, envp);
    }

    struct pagemap_t *new_pagemap = new_address_space();

    struct auxval_t auxval;
    char *ld_path;

    ret = elf_load(fd, new_pagemap, 0, &auxval, &ld_path);
    close(fd);
    if (ret == -1) {
        kprint(KPRN_DBG, "elf: Load of binary file %s failed.", filename);
        free_address_space(new_pagemap);
        return -1;
    }

    // If requested: Load the dynamic linker
    if (!ld_path) {
        entry = auxval.at_entry;
    } else {
        int ld_fd = open(ld_path, O_RDONLY);
        if (ld_fd < 0) {
            kprint(KPRN_DBG, "elf: Could not find dynamic linker.");
            free_address_space(new_pagemap);
            kfree(ld_path);
            return -1;
        }

        // 1 GiB is chosen arbitrarily (as programs are expected to fit below 1 GiB).
        //   TODO: Dynamically find a virtual address range that is large enough
        struct auxval_t ld_auxval;
        ret = elf_load(ld_fd, new_pagemap, 0x40000000, &ld_auxval, NULL);
        close(ld_fd);
        if (ret == -1) {
            kprint(KPRN_DBG, "elf: Load of binary file %s failed.", ld_path);
            free_address_space(new_pagemap);
            kfree(ld_path);
            return -1;
        }
        kfree(ld_path);
        entry = ld_auxval.at_entry;
    }

    // Map the higher half into the process
    for (size_t i = 256; i < 512; i++) {
        new_pagemap->pml4[i] = process_table[0]->pagemap->pml4[i];
    }

    // Destroy all previous threads
    for (size_t i = 0; i < MAX_THREADS; i++)
        task_tkill(pid, i);

    // Map the sig ret trampoline into process
    void *trampoline_ptr = pmm_allocz(1);
    memcpy(trampoline_ptr + MEM_PHYS_OFFSET,
            signal_trampoline,
            (size_t)signal_trampoline_size);
    map_page(new_pagemap,
             (size_t)trampoline_ptr,
             (size_t)(SIGNAL_TRAMPOLINE_VADDR),
             0x05,
             VMM_ATTR_REG);

    // Free previous address space
    free_address_space(old_pagemap);

    // Load new pagemap
    process->pagemap = new_pagemap;

    // Create main thread
    task_tcreate(pid, tcreate_elf_exec, tcreate_elf_exec_data((void *)entry, argv, envp, &auxval));

    return 0;
*/
}
