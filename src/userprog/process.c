
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include <stdlib.h>

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  // printf("\n=== PROCESS_EXECUTE START ===\n");
  // printf("DEBUG: file_name = '%s'\n", file_name);
  // printf("DEBUG: Current thread tid = %d, name = '%s'\n", 
        //  thread_current()->tid, thread_current()->name);
  
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  // printf("DEBUG: Allocating page for fn_copy\n");
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL) {
    // printf("ERROR: palloc_get_page failed for fn_copy\n");
    // printf("=== PROCESS_EXECUTE END (returning TID_ERROR) ===\n\n");
    return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);
  // printf("DEBUG: fn_copy created successfully = '%s'\n", fn_copy);

  char *name_copy = palloc_get_page (0);
  strlcpy(name_copy, file_name, PGSIZE);

  char *save_ptr;
  char *prog = strtok_r(name_copy, " ", &save_ptr);
  if (prog == NULL) prog = name_copy;

  // Create child_process metadata FIRST
  // printf("DEBUG: Allocating child_process struct\n");
  struct child_process *cp = malloc(sizeof(struct child_process));
  if (cp == NULL) {
    // printf("ERROR: malloc failed for child_process\n");
    palloc_free_page(fn_copy);
    // printf("=== PROCESS_EXECUTE END (returning TID_ERROR) ===\n\n");
    return TID_ERROR;
  }
  // printf("DEBUG: child_process allocated at %p\n", cp);

  // Initialize child_process fields
  cp->parent = thread_current();
  cp->is_parent_blocking = false;
  cp->has_exited = false;
  cp->exitcode = -1;
  cp->load_success = false;  // Initialize to false
  sema_init(&cp->sema_initialization, 0);
  sema_init(&cp->sema_wait, 0);
  // printf("DEBUG: child_process initialized:\n");
  // printf("       - parent = %p\n", cp->parent);
  // printf("       - is_parent_blocking = %d\n", cp->is_parent_blocking);
  // printf("       - has_exited = %d\n", cp->has_exited);
  // printf("       - exitcode = %d\n", cp->exitcode);
  // printf("       - load_success = %d\n", cp->load_success);

  struct thread *cur = thread_current();
  if (cur->cwd != NULL){
    cp->parent_cwd = dir_reopen(cur->cwd);
  }
  else{
    cp->parent_cwd = dir_open_root();
  }

  /* Create a new thread to execute FILE_NAME. */
  // printf("DEBUG: Calling thread_create with name='%s'\n", file_name);
  tid = thread_create (prog, PRI_DEFAULT, start_process, fn_copy);
  
  if (tid == TID_ERROR) {

    //printf("\nERROR: thread_create failed\n");
    free(cp);
    palloc_free_page (fn_copy);
    // printf("=== PROCESS_EXECUTE END (returning TID_ERROR) ===\n\n");
    return TID_ERROR;
  }

  cp->pid = tid;
  // printf("DEBUG: Thread created successfully with tid = %d\n", tid);
  // printf("DEBUG: Set cp->pid = %d\n", cp->pid);
  
  // Add to parent's child list
  // printf("DEBUG: Adding child_process to parent's child_list\n");
  list_push_back(&thread_current()->child_list, &cp->elem);
  // printf("DEBUG: child_process added to list\n");

  // Find the child thread and link it to cp
  // printf("DEBUG: Looking up child thread with tid = %d\n", tid);
  struct thread *child = thread_get_by_tid(tid);  // Use proper function!
  if (child != NULL) {
    // printf("DEBUG: Found child thread at %p\n", child);
    // printf("DEBUG: Child thread name = '%s', tid = %d\n", child->name, child->tid);
    child->my_child_info = cp;
    // printf("DEBUG: Linked child->my_child_info = %p\n", child->my_child_info);
  } else {
    // printf("ERROR: Could not find child thread with tid = %d\n", tid);
    // printf("WARNING: Child will not be able to signal parent!\n");
  }

  // Wait for child to finish loading
  // printf("DEBUG: Parent waiting for child to load (calling sema_down)...\n");
  sema_down(&cp->sema_initialization);
  // printf("DEBUG: Parent woke up from sema_down!\n");

  // Check if load was successful
  //printf("DEBUG: Checking cp->load_success = %d\n", cp->load_success);
  if (!cp->load_success) {
    //printf("ERROR: Child load failed!\n");
    // printf("DEBUG: Cleaning up: removing from list and freeing\n");
    list_remove(&cp->elem);
    free(cp);
    // printf("=== PROCESS_EXECUTE END (returning TID_ERROR due to load failure) ===\n\n");
    return TID_ERROR;
  }

  // printf("DEBUG: Child loaded successfully!\n");
  // printf("=== PROCESS_EXECUTE END (returning tid=%d) ===\n\n", tid);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  // printf("\n=== START_PROCESS BEGIN ===\n");
  
  char *file_name = file_name_;
  // printf("DEBUG: file_name_ pointer = %p\n", file_name_);
  // printf("DEBUG: file_name = '%s'\n", file_name);
  
  struct thread *cur = thread_current();
  // printf("DEBUG: Current thread:\n");
  // printf("       - thread pointer = %p\n", cur);
  // printf("       - tid = %d\n", cur->tid);
  // printf("       - name = '%s'\n", cur->name);
  // printf("       - my_child_info = %p\n", cur->my_child_info);

  /* Grab the child_process metadata pointer set by process_execute(). */
  struct child_process *cp = cur->my_child_info;
  
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  // printf("DEBUG: Initializing interrupt frame\n");
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // printf("DEBUG: Interrupt frame initialized\n");
  // printf("       - if_.gs = 0x%x\n", if_.gs);
  // printf("       - if_.cs = 0x%x\n", if_.cs);
  // printf("       - if_.ss = 0x%x\n", if_.ss);

  // printf("DEBUG: About to call load() with file_name = '%s'\n", file_name);
  success = load (file_name, &if_.eip, &if_.esp);
  // printf("DEBUG: load() returned success = %d\n", success);
  // printf("DEBUG: After load:\n");
  // printf("       - if_.eip = %p\n", if_.eip);
  // printf("       - if_.esp = %p\n", if_.esp);

  /* Install or clean up cwd based on load() result. */
  if (cp != NULL) {
    if (success) {
      /* Child successfully loaded: take ownership of parent_cwd as our cwd. */
      if (cur->cwd != NULL) {
        dir_close(cur->cwd);
      }
      cur->cwd = cp->parent_cwd;
      cp->parent_cwd = NULL;
    } else {
      /* Load failed: just close the captured parent_cwd. */
      if (cp->parent_cwd != NULL) {
        dir_close(cp->parent_cwd);
        cp->parent_cwd = NULL;
      }
    }
  }

  // ===== SIGNAL PARENT BEFORE ANYTHING ELSE =====
  // printf("DEBUG: ===== SIGNALING PARENT =====\n");
  // printf("DEBUG: Checking my_child_info = %p\n", cur->my_child_info);
  
  if (cur->my_child_info != NULL) {
    // printf("DEBUG: my_child_info is valid, setting load_success\n");
    // printf("DEBUG: Setting my_child_info->load_success = %d\n", success);
    cur->my_child_info->load_success = success;
    
    // printf("DEBUG: Calling sema_up on sema_initialization\n");
    // printf("DEBUG: sema_initialization value before = %d\n", 
          //  cur->my_child_info->sema_initialization.value);
    sema_up(&cur->my_child_info->sema_initialization);
    // printf("DEBUG: sema_up completed\n");
    // printf("DEBUG: sema_initialization value after = %d\n", 
          //  cur->my_child_info->sema_initialization.value);
    // printf("DEBUG: Parent should now wake up\n");
  } else {
    // printf("ERROR: my_child_info is NULL!\n");
    // printf("ERROR: Cannot signal parent - parent will block forever!\n");
  }
  // printf("DEBUG: ===== END SIGNALING PARENT =====\n");
  // ===== END CRITICAL SECTION =====

  /* If load failed, quit. */
  // printf("DEBUG: Freeing file_name page at %p\n", file_name);
  palloc_free_page (file_name);
  // printf("DEBUG: file_name page freed\n");
  
  if (!success) {
    // printf("ERROR: Load failed (success = %d)\n", success);
    // printf("DEBUG: Calling thread_exit()\n");
    // printf("=== START_PROCESS END (load failed, exiting) ===\n\n");
    thread_exit ();
  }

  // printf("DEBUG: Load succeeded! Preparing to start user process\n");
  // printf("DEBUG: Final interrupt frame values:\n");
  // printf("       - eip (entry point) = %p\n", if_.eip);
  // printf("       - esp (stack pointer) = %p\n", if_.esp);
  // printf("       - eflags = 0x%x\n", if_.eflags);
  // printf("DEBUG: About to jump to user mode via intr_exit\n");
  // printf("=== START_PROCESS END (jumping to user mode) ===\n\n");

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // printf("\n=== PROCESS_WAIT START ===\n");
  // printf("DEBUG: requested child_tid = %d\n", child_tid);

  struct thread *cur = thread_current();
  // printf("DEBUG: current thread: %p (tid=%d, name='%s')\n", cur, cur->tid, cur->name);

  struct list_elem *e;
  struct child_process *target_cp = NULL;

  /* Scan child list. */
  // printf("DEBUG: scanning child_list @ %p\n", &cur->child_list);
  int idx = 0;
  for (e = list_begin(&cur->child_list);
       e != list_end(&cur->child_list);
       e = list_next(e)) 
  {
    struct child_process *cp = list_entry(e, struct child_process, elem);
    // printf("DEBUG: child[%d]: cp=%p pid=%d exited=%d exitcode=%d blocking=%d\n",
    //        idx, cp, cp->pid, cp->has_exited, cp->exitcode, cp->is_parent_blocking);
    if (cp->pid == child_tid) {
      target_cp = cp;
      // printf("DEBUG: MATCH: target_cp=%p for pid=%d\n", target_cp, child_tid);
      break;
    }
    idx++;
  }

  if (target_cp == NULL) {
    // printf("ERROR: child_tid %d not found in current thread's child_list\n", child_tid);
    // printf("=== PROCESS_WAIT END (fail, -1) ===\n");
    return -1; // Not a child or already reaped
  }

  if (target_cp->is_parent_blocking) {
    // printf("ERROR: already waiting on child_tid %d (is_parent_blocking==true)\n", child_tid);
    // printf("=== PROCESS_WAIT END (fail, -1) ===\n");
    return -1; // process_wait called twice on same child
  }

  /* Block until the child exits (if not already). */
  // printf("DEBUG: setting is_parent_blocking=true for cp=%p (pid=%d)\n",
  //        target_cp, target_cp->pid);
  target_cp->is_parent_blocking = true;

  if (!target_cp->has_exited) {
    // printf("DEBUG: child pid=%d has_exited=0 -> sema_down(&sema_wait)\n", target_cp->pid);
    sema_down(&target_cp->sema_wait);
    // printf("DEBUG: woke up from sema_down; child pid=%d should be exited now\n", target_cp->pid);
  } else {
    // printf("DEBUG: child pid=%d already exited (has_exited=1); skipping sema_down\n", target_cp->pid);
  }

  /* Collect exit status. */
  int exit_status = target_cp->exitcode;
  // printf("DEBUG: child pid=%d exit_status=%d\n", target_cp->pid, exit_status);

  /* Cleanup this child_process entry from the parent's list. */
  // printf("DEBUG: removing cp=%p (pid=%d) from parent child_list\n", target_cp, target_cp->pid);
  list_remove(&target_cp->elem);

  /* If your design frees cp here, uncomment:
     // printf("DEBUG: freeing cp=%p\n", target_cp);
     // free(target_cp);
  */

  // printf("=== PROCESS_WAIT END (return %d) ===\n", exit_status);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if (cur->executable != NULL) {
    file_allow_write (cur->executable);
    file_close (cur->executable);
    cur->executable = NULL;
  }

  /* Close current working directory if any. */
  if (cur->cwd != NULL) {
    dir_close(cur->cwd);
    cur->cwd = NULL;
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}
/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, int commandline_size, char* command_line);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  // printf("Load called\n");
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */

  char *token, *save_ptr;
  char names[100];
  char *args[100];
  strlcpy (names, file_name, sizeof names);
  int j = 0;
  for (token = strtok_r(names, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)){
    args[j] = token;
    j++;
  }

  file = file_open(filesys_open (args[0]));
  struct inode *inode = filesys_open(args[0]);
  if (inode == NULL)
    goto done;

  file = file_open(inode);
  if (file == NULL) 
    {
      // printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  // printf("OPen finished\n");

  file_deny_write (file);
  t->executable = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      // printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, sizeof(file_name), file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
    if (!success && file != NULL && t->executable == NULL) {
    file_close (file);
  }
  // file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

static void *
push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size)
{
  // size_t padsize = ROUND_UP (size, sizeof (uint32_t));
  size_t padsize = size;
  // size_t padsize = size;
  if (*ofs < padsize)
    return NULL;

  *ofs -= padsize;
  memcpy (kpage + *ofs + (padsize - size), buf, size);
  return kpage + *ofs + (padsize - size);
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, int commandline_size, char* command_line) 
{
  // printf("\n=== SETUP_STACK START ===\n");
  // printf("DEBUG: command_line = '%s'\n", command_line);
  // printf("DEBUG: PHYS_BASE = %p\n", PHYS_BASE);

  uint8_t *kpage = NULL;
  uint8_t *userpage = NULL;
  bool success = false;

  /* --- Scratch buffers moved off kernel stack --- */
  char *names = NULL;              /* 4 KB scratch for tokenization */
  char **tokens = NULL;            /* argv tokens (host pointers)   */
  void **adrss  = NULL;            /* user-space argv[i] addresses  */

  /* Basic input check. */
  if (strlen(command_line) >= PGSIZE) {
    // printf("ERROR: Command line too long\n");
    goto out_fail_nothing;
  }

  /* Allocate the user stack page. */
  // printf("DEBUG: Allocating stack page\n");
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage == NULL) {
    // printf("ERROR: Failed to allocate stack page\n");
    goto out_fail_nothing;
  }
  // printf("DEBUG: Stack page allocated at %p\n", kpage);

  userpage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  // printf("DEBUG: User page address = %p\n", userpage);

  if (!install_page (userpage, kpage, true)) {
    // printf("ERROR: install_page failed\n");
    goto out_fail_stack_page;
  }
  // printf("DEBUG: Stack page installed successfully\n");

  /* Allocate large temporaries safely. */
  names  = palloc_get_page (0);               /* 4 KB scratch */
  tokens = malloc(sizeof(char*) * 128);
  adrss  = malloc(sizeof(void*) * 128);
  if (names == NULL || tokens == NULL || adrss == NULL) {
    // printf("ERROR: Failed to allocate scratch buffers (names=%p tokens=%p adrss=%p)\n",
          //  names, tokens, adrss);
    goto out_fail_scratch;
  }

  strlcpy (names, command_line, PGSIZE);

  /* Tokenize command line. */
  // printf("DEBUG: Tokenizing command line\n");
  int token_count = 0;
  {
    char *save_ptr = NULL;
    for (char *tok = strtok_r(names, " ", &save_ptr);
         tok != NULL;
         tok = strtok_r(NULL, " ", &save_ptr))
    {
      if (token_count >= 128) {
        // printf("ERROR: Too many arguments (>127)\n");
        goto out_fail_scratch;
      }
      tokens[token_count] = tok;
      // printf("DEBUG: Token[%d] = '%s'\n", token_count, tok);
      token_count++;
    }
  }
  // printf("DEBUG: Total token_count = %d\n", token_count);

  /* Begin building stack (top-down in kpage). */
  size_t traveler = PGSIZE;   /* Bytes remaining from top of kpage */
  void *pushed_to = NULL;
  void *pushed_ret = NULL;

  /* Push argument strings in reverse order; remember user addresses. */
  // printf("\nDEBUG: Pushing argument strings\n");
  for (int i = token_count - 1; i >= 0; i--) {
    const char *s = tokens[i];
    size_t len = strlen(s) + 1;
    // printf("DEBUG: Pushing token[%d] = '%s' (length=%zu)\n", i, s, len);
    void *adr = push (kpage, &traveler, s, len);
    if (adr == NULL) {
      // printf("ERROR: push failed for token[%d]\n", i);
      goto out_fail_scratch;
    }
    /* Convert kernel-page pointer to user virtual address. */
    void *user_arg = userpage + ((char *)adr - (char *)kpage);
    adrss[i] = user_arg;
    // printf("DEBUG: adrss[%d] = %p (traveler=%zu)\n", i, adrss[i], traveler);
  }

  /* Word-align the stack pointer before pushing pointers/ints. */
  // printf("\nDEBUG: Word-aligning stack (before: %zu)\n", traveler);
  traveler = ROUND_DOWN (traveler, sizeof (uint32_t));
  // printf("DEBUG: After alignment: %zu\n", traveler);

  /* Push NULL sentinel for argv[argc]. */
  // printf("\nDEBUG: Pushing NULL sentinel for argv[%d]\n", token_count);
  void *null_ptr = NULL;
  pushed_to = push (kpage, &traveler, &null_ptr, sizeof null_ptr);
  if (pushed_to == NULL) {
    // printf("ERROR: push failed for NULL sentinel\n");
    goto out_fail_scratch;
  }
  // printf("DEBUG: NULL sentinel pushed at traveler=%zu\n", traveler);

  /* Push pointers to the argument strings: argv[argc-1]..argv[0]. */
  // printf("\nDEBUG: Pushing argv pointers\n");
  for (int j = token_count - 1; j >= 0; j--) {
    // printf("DEBUG: Pushing argv[%d] = %p\n", j, adrss[j]);
    pushed_to = push (kpage, &traveler, &adrss[j], sizeof(adrss[j]));
    if (pushed_to == NULL) {
      // printf("ERROR: push failed for argv[%d]\n", j);
      goto out_fail_scratch;
    }
    // printf("DEBUG: argv[%d] pushed at traveler=%zu\n", j, traveler);
  }

  /* Push argv (pointer to argv[0] in user space). */
  // printf("\nDEBUG: Pushing argv pointer\n");
  void *user_argv = userpage + ((char *)pushed_to - (char *)kpage);
  // printf("DEBUG: user_argv = %p\n", user_argv);
  void *pushed_argv = push (kpage, &traveler, &user_argv, sizeof user_argv);
  if (pushed_argv == NULL) {
    // printf("ERROR: push failed for argv\n");
    goto out_fail_scratch;
  }
  // printf("DEBUG: argv pushed at traveler=%zu\n", traveler);

  /* Push argc. */
  // printf("\nDEBUG: Pushing argc = %d\n", token_count);
  void *pushed_argc = push (kpage, &traveler, &token_count, sizeof token_count);
  if (pushed_argc == NULL) {
    // printf("ERROR: push failed for argc\n");
    goto out_fail_scratch;
  }
  // printf("DEBUG: argc pushed at traveler=%zu\n", traveler);

  /* Push fake return address. */
  // printf("\nDEBUG: Pushing fake return address\n");
  void *fake_ret = NULL;
  pushed_ret = push (kpage, &traveler, &fake_ret, sizeof fake_ret);
  if (pushed_ret == NULL) {
    // printf("ERROR: push failed for fake return address\n");
    goto out_fail_scratch;
  }
  // printf("DEBUG: Fake return address pushed at traveler=%zu\n", traveler);

  /* Set ESP to point at the fake return address. */
  *esp = userpage + ((char *)pushed_ret - (char *)kpage);

  // printf("\nDEBUG: Calculating ESP:\n");
  // printf("       - userpage = %p\n", userpage);
  // printf("       - pushed_ret offset in kpage = %zu\n", (size_t)((char*)pushed_ret - (char*)kpage));
  // printf("       - ESP = %p\n", *esp);

  // printf("\nDEBUG: Stack layout hints:\n");
  // printf("       ESP   (%p) -> fake return address\n", *esp);
  // printf("       ESP+4 (%p) -> argc = %d\n", (char*)*esp + 4, token_count);
  // printf("       ESP+8 (%p) -> argv\n", (char*)*esp + 8);

  // printf("\nDEBUG: Stack contents (hex dump):\n");
  // hex_dump((uintptr_t)*esp, *esp, 100, true);

  success = true;
  // printf("=== SETUP_STACK END (success=%d) ===\n\n", success);

  /* Cleanup scratch buffers; keep mapped stack page. */
  free(tokens);
  free(adrss);
  palloc_free_page(names);
  return success;

/* ---- Failure paths with proper cleanup ---- */
out_fail_scratch:
  if (tokens) free(tokens);
  if (adrss)  free(adrss);
  if (names)  palloc_free_page(names);
  /* fallthrough */
out_fail_stack_page:
  /* Keep kpage mapped only if success; on failure, if we installed it,
     it will be reclaimed when the process is torn down. If you prefer,
     you could also explicitly clear the mapping here. */
  // printf("=== SETUP_STACK END (success=0) ===\n\n");
  return false;

out_fail_nothing:
  // printf("=== SETUP_STACK END (success=0) ===\n\n");
  return false;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
