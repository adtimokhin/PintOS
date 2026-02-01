#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"   // for exit(-1)

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

void
exception_init (void)
{
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

void
exception_print_stats (void)
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* For non-page-fault exceptions, keep default behavior. */
static void
kill (struct intr_frame *f)
{
  switch (f->cs)
  {
    case SEL_UCSEG:
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      exit(-1);    
      NOT_REACHED();

    case SEL_KCSEG:
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel");

    default:
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
              f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
  }
}


static void
page_fault (struct intr_frame *f)
{
  void *fault_addr;

  /* Read CR2 (faulting linear address) while ints are off. */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  intr_enable();            /* Re-enable interrupts. */
  page_fault_cnt++;

  bool user  = (f->error_code & PF_U) != 0;
  /* (not_present, write) are not needed for these tests, but harmless to keep:
     bool not_present = (f->error_code & PF_P) == 0;
     bool write       = (f->error_code & PF_W) != 0;
  */

  if (!user) {
    /* Fault occurred in kernel mode, almost certainly inside get_user/put_user.
       Assembly in those helpers sets EAX to a "resume label" address on fault.
       We must:
         - set EIP to that resume address to skip the faulting memory op
         - set EAX to a sentinel so the helper returns failure
             get_user   -> return -1  (0xffffffff)
             put_user   -> return false (we also use 0xffffffff; your put_user
                             checks error_code != -1, so it will return false) */
    f->eip = (void *) f->eax;
    f->eax = 0xffffffff; 
    return;
  }

  exit(-1);
  NOT_REACHED();
}