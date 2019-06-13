#ifndef __CPU_H__
#define __CPU_H__

#include <stddef.h>
#include <stdint.h>
#include <lib/types.h>

#define MAX_CPUS 128

#define current_cpu ({ \
    size_t cpu_number; \
    asm volatile ("mov %0, qword ptr gs:[0]" \
                    : "=r" (cpu_number) \
                    : \
                    : "memory", "cc"); \
    (int)cpu_number; \
})

struct cpu_local_t {
    /* DO NOT MOVE THESE MEMBERS FROM THESE LOCATIONS */
    /* DO NOT CHANGE THEIR TYPES */
    size_t cpu_number;
    size_t kernel_stack;
    size_t thread_kstack;
    size_t thread_ustack;
    size_t thread_errno;
    size_t ipi_abort_received;
    /* Feel free to move every other member, and use any type as you see fit */
    tid_t current_task;
    pid_t current_process;
    tid_t current_thread;
    uint8_t lapic_id;
    int ipi_abortexec_received;
    int ipi_resched_received;
};

extern struct cpu_local_t cpu_locals[MAX_CPUS];

#endif
