#include <stdint.h>
#include <stddef.h>
#include <lib/cio.h>
#include <lib/klib.h>
#include <sys/e820.h>
#include <mm/mm.h>
#include <sys/idt.h>
#include <sys/pic.h>
#include <acpi/acpi.h>
#include <lib/cmdline.h>
#include <sys/pit.h>
#include <sys/smp.h>
#include <sys/sched.h>
#include <lib/time.h>
#include <sys/irq.h>
#include <sys/panic.h>
#include <lib/rand.h>

void kmain_thread(void *arg) {
    (void)arg;

    kprint(KPRN_INFO, "kmain: End of kmain");

    /* kill kmain now */
    task_tkill(CURRENT_PROCESS, CURRENT_THREAD);

    for (;;) asm volatile ("hlt;");
}

/* Main kernel entry point, only initialise essential services and scheduler */
void kmain(void) {
    kprint(KPRN_INFO, "Kernel booted");
    kprint(KPRN_INFO, "Command line: %s", cmdline);

    init_idt();

    /* Memory-related stuff */
    init_e820();
    init_pmm();
    init_rand();
    init_vmm();

    /* Time stuff */
    struct s_time_t s_time;
    bios_get_time(&s_time);
    kprint(KPRN_INFO, "Current date & time: %u/%u/%u %u:%u:%u",
           s_time.years, s_time.months, s_time.days,
           s_time.hours, s_time.minutes, s_time.seconds);
    unix_epoch = get_unix_epoch(s_time.seconds, s_time.minutes, s_time.hours,
                                s_time.days, s_time.months, s_time.years);
    kprint(KPRN_INFO, "Current unix epoch: %U", unix_epoch);

    /*** NO MORE REAL MODE CALLS AFTER THIS POINT ***/
    flush_irqs();
    init_acpi();
    init_pic();

    init_pit();

    /* Enable interrupts on BSP */
    asm volatile ("sti");

    init_smp();

    /* Initialise scheduler */
    init_sched();

    /* Unlock the scheduler for the first time */
    spinlock_release(&scheduler_lock);

    /* Start a main kernel thread which will take over when the scheduler is running */
    task_tcreate(0, tcreate_fn_call, tcreate_fn_call_data(0, kmain_thread, 0));

    /*** DO NOT ADD ANYTHING TO THIS FUNCTION AFTER THIS POINT, ADD TO kmain_thread
         INSTEAD! ***/

    /* Pre-scheduler init done. Wait for the main kernel thread to be scheduled. */
    for (;;) asm volatile ("hlt");
}
