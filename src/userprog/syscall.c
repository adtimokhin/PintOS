#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/file.h"

typedef int pid_t;


////////////////////////////////////////////////////////////////////////////////
//                            Handler Definitions
////////////////////////////////////////////////////////////////////////////////
static void syscall_handler (struct intr_frame *);        /* Default */

void halt (void);                                         /* Halt the operating system. */
void exit (int status);                                   /* Terminate this process. */
pid_t exec (const char *cmd_line);                        /* Start another process. */
int wait (pid_t pid);                                     /* Wait for a child process to die. */
bool create (const char *file, unsigned initial_size);    /* Create a file. */
bool remove (const char *file);                           /* Delete a file. */
int open (const char *file);                              /* Open a file. */
int filesize (int handle);                                /* Obtain a file's size. */
int read (int fd, void *buffer, unsigned size);           /* Read from a file. */
int write (int handle, const void *buffer, unsigned size);/* Write to a file. */
void seek (int fd, unsigned position);                    /* Change position in a file. */
unsigned tell (int fd);                                   /* Report current position in a file. */
void close (int fd);                                      /* Close a file. */
bool chdir (const char *dir);                             /* Changes the current working directory. */
bool mkdir (const char *dir);                             /* Creates the directory named dir. */
bool readdir (int fd, char *name);                        /* Reads a directory entry from file descriptor. */
bool isdir (int fd);                                      /* Returns true if fd represents a directory. */
int inumber (int fd);                                     /* Returns the inode number of the inode associated with fd. */
static int copy_bytes(void *from, void *to, size_t byte_count);
static void* user_to_kernel_vaddr (void *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int get_user (const uint8_t *uaddr);
struct file_descriptor* lookup_fd(int id, struct list *fd_table);
struct file_descriptor * remove_fd_table_row (struct list *fd_table, struct file_descriptor *fd);
static void fail_invalid_access(void);
static void check_user (const uint8_t *uaddr);
static void validate_user_writable_range (void *uaddr, unsigned size);
static void validate_user_readable_range (const void *uaddr, unsigned size);


////////////////////////////////////////////////////////////////////////////////
//                         Main Function Implementations
////////////////////////////////////////////////////////////////////////////////

struct lock file_lock; // Lock used when kernel tries to use the file system.

void
syscall_init (void) 
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
  This is a general handler that is called to handle syscall interrupt.
  When a process calls for a syscall interupt, it must set the syscall 
  number into esp of the stack frame.

  Current implementation (for P2) supports the following syscall numbers:
  
  SYS_HALT      -> 0
  SYS_EXIT      -> 1
  SYS_EXEC      -> 2
  SYS_WAIT      -> 3
  SYS_CREATE    -> 4
  SYS_REMOVE    -> 5
  SYS_OPEN      -> 6
  SYS_FILESIZE  -> 7
  SYS_READ      -> 8
  SYS_WRITE     -> 9
  SYS_SEEK      -> 10
  SYS_TELL      -> 11
  SYS_CLOSE     -> 12

  Args:
    f (intr_frame *) - reference to a process frame that made the system call.

*/
static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num;
  void *esp_pointer = f->esp;
  copy_bytes(f->esp, &syscall_num, sizeof(syscall_num));

  switch(syscall_num){
    case SYS_HALT: {
      halt();
      NOT_REACHED(); // In case halt() handler fails.
      break;
    }
    case SYS_EXIT: {
      int status;
      void *argp = (uint8_t *)f->esp + 4;

      // Fast, explicit guard for sc-bad-arg:
      if (argp == NULL ||
          !is_user_vaddr(argp) ||
          pagedir_get_page(thread_current()->pagedir, argp) == NULL) {
        exit(-1); NOT_REACHED();
      }

      if (copy_bytes(argp, &status, sizeof status) < 0) {
        exit(-1); NOT_REACHED();
      }

      exit(status);
      NOT_REACHED();
    }
    case SYS_EXEC: {
      const char *u_cmd;
      if (copy_bytes((uint8_t *)f->esp + 4, &u_cmd, sizeof u_cmd) < 0) {
        f->eax = (uint32_t)-1;
        break;
      }

      pid_t pid = exec(u_cmd);

      f->eax = (uint32_t) pid;
      break;
    }
    case SYS_WAIT: {
      pid_t pid;
      copy_bytes(f->esp + 4, &pid, sizeof(pid_t));

      int ret = wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_CREATE: {
      const char* filename;
      unsigned initial_size;

      copy_bytes(f->esp + 4, &filename, sizeof(filename));
      copy_bytes(f->esp + 8, &initial_size, sizeof(initial_size));

      /* Debug: show raw user arguments. */
      // printf("=== SYS_CREATE START ===\n");
      // printf("SYS_CREATE: raw filename ptr=%p, initial_size=%u\n",(void *)filename, initial_size);

      int ret = create(filename, initial_size);

      // printf("SYS_CREATE: create() -> %d\n", ret);
      // printf("=== SYS_CREATE END ===\n");

      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_REMOVE: {
      const char *filename;
      copy_bytes(f->esp + 4, &filename, sizeof(filename));

      bool ret = remove(filename);
      f->eax = ret ? 1 : 0; // True = 1 | False = 0
      break;
    }
    case SYS_OPEN: {
      const char *filename;
      copy_bytes(f->esp + 4, &filename, sizeof(filename));

      int ret = open(filename);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_FILESIZE: {
      int handle;
      copy_bytes(f->esp + 4, &handle, sizeof(handle));

      int ret = filesize(handle);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_READ: {
      int fd; void *buffer; unsigned size;
      if (copy_bytes((uint8_t *)f->esp + 4,  &fd,     sizeof fd)   < 0 ||
          copy_bytes((uint8_t *)f->esp + 8,  &buffer, sizeof buffer)< 0 ||
          copy_bytes((uint8_t *)f->esp + 12, &size,   sizeof size) < 0) {
        exit(-1); NOT_REACHED();
      }

      validate_user_readable_range(buffer, size);

      f->eax = (uint32_t) read(fd, buffer, size);
      break;
    }
    case SYS_WRITE: {
      int handle;
      const void* buffer;
      unsigned size;

      copy_bytes(f->esp + 4, &handle, sizeof(handle));
      copy_bytes(f->esp + 8, &buffer, sizeof(buffer));
      copy_bytes(f->esp + 12, &size, sizeof(size));

      validate_user_writable_range(buffer, size);

      int ret = write(handle, buffer, size);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_SEEK: {
      int fd; unsigned position;
      if (copy_bytes((uint8_t *)f->esp + 4, &fd, sizeof fd) < 0 ||
          copy_bytes((uint8_t *)f->esp + 8, &position, sizeof position) < 0) {
        exit(-1); NOT_REACHED();
      }
      seek(fd, position);
      break;
    }

    case SYS_TELL: {
      int fd;
      if (copy_bytes((uint8_t *)f->esp + 4, &fd, sizeof fd) < 0) {
        exit(-1); NOT_REACHED();
      }
      f->eax = (uint32_t) tell(fd);
      break;
    }
    case SYS_CLOSE: {
      int handle;
      copy_bytes(f->esp + 4, &handle, sizeof(handle));

      close(handle);
      break;
    }
        case SYS_CHDIR: {
      const char *dir;
      copy_bytes((uint8_t *)f->esp + 4, &dir, sizeof dir);

      bool ret = chdir(dir);
      f->eax = ret ? 1 : 0;
      break;
    }
    case SYS_MKDIR: {
      const char *dir;
      copy_bytes((uint8_t *)f->esp + 4, &dir, sizeof dir);

      bool ret = mkdir(dir);
      f->eax = ret ? 1 : 0;
      break;
    }
    case SYS_READDIR: {
      int fd;
      char *name;

      if (copy_bytes((uint8_t *)f->esp + 4, &fd,   sizeof fd)   < 0 ||
          copy_bytes((uint8_t *)f->esp + 8, &name, sizeof name) < 0) {
        exit(-1); NOT_REACHED();
      }

      bool ret = readdir(fd, name);
      f->eax = ret ? 1 : 0;
      break;
    }
    case SYS_ISDIR: {
      int fd;
      if (copy_bytes((uint8_t *)f->esp + 4, &fd, sizeof fd) < 0) {
        exit(-1); NOT_REACHED();
      }

      bool ret = isdir(fd);
      f->eax = ret ? 1 : 0;
      break;
    }
    case SYS_INUMBER: {
      int fd;
      if (copy_bytes((uint8_t *)f->esp + 4, &fd, sizeof fd) < 0) {
        exit(-1); NOT_REACHED();
      }

      int ret = inumber(fd);
      f->eax = (uint32_t) ret;
      break;
    }
    default:{
      exit(-1);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
//                             SYSCALL Handlers
////////////////////////////////////////////////////////////////////////////////

void halt (void){
  shutdown_power_off();
}

void exit (int status){
  struct thread * current_thread = thread_current();
  struct child_process* child_process_info = current_thread->my_child_info;
  
  if (child_process_info != NULL){
    // This process is a child of some other process!
    child_process_info->has_exited = true;
    child_process_info->exitcode = status;
    sema_up(&child_process_info->sema_wait);
  }
  
  printf("%s: exit(%d)\n", current_thread->name, status);
  thread_exit();
}

pid_t exec (const char *cmd_line){

  if (cmd_line == NULL)
    return -1;

  check_user((const uint8_t*) cmd_line);

  cmd_line = user_to_kernel_vaddr (cmd_line);

  
  tid_t child_tid = process_execute (cmd_line);

  if (child_tid == TID_ERROR){
    return -1;
  }
  return child_tid;
}

int wait (pid_t pid){
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  bool success;

  /* Validate the user pointer first. */
  check_user((const uint8_t*) file);

  /* Translate to a kernel virtual address so we can safely printf it. */
  file = user_to_kernel_vaddr ((void *)file);

  /* For now, sys_create always creates regular files (FILE_INODE). */
  enum inode_type type = FILE_INODE;

  const char *type_str = "UNKNOWN";
  if (type == FILE_INODE) type_str = "FILE";
  else if (type == DIR_INODE) type_str = "DIR";

  // printf("syscall_create: name='%s', initial_size=%u, type=%d (%s)\n", file ? file : "(null)", initial_size, (int)type, type_str);

  lock_acquire(&file_lock);
  success = filesys_create(file, initial_size, type);
  lock_release(&file_lock);

  // printf("syscall_create: filesys_create(...) -> %s\n", success ? "true" : "false");

  return success;
}

bool remove (const char *file){
  file = user_to_kernel_vaddr (file);

  check_user((const uint8_t*) file);
  bool success = false;
  lock_acquire (&file_lock);
  // printf("syscal - remove: TRYING TO REMOVE file");
  success = filesys_remove(file);
  // printf("syscal - remove: REMOVED file SUCCESSFULLY");
  lock_release (&file_lock);
  
  return success;
}

// our open returns the file_id of a file descriptor
int open (const char *file) {
  check_user((const uint8_t *) file);

  if (file == NULL) {
    return -1;
  }

  struct thread *cur = thread_current();
  struct file_descriptor *new_fd = NULL;
  struct inode *inode = NULL;

  lock_acquire(&file_lock);

  /* First resolve the path into an inode. */
  inode = filesys_open(file);
  if (inode == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  /* Allocate a descriptor node. */
  new_fd = malloc(sizeof *new_fd);
  if (new_fd == NULL) {
    inode_close(inode);
    lock_release(&file_lock);
    return -1;
  }

  enum inode_type type = inode_get_type(inode);

  if (type == DIR_INODE) {
    /* Open as directory FD. */
    struct dir *d = dir_open(inode);
    if (d == NULL) {
      inode_close(inode);
      free(new_fd);
      lock_release(&file_lock);
      return -1;
    }

    new_fd->is_dir  = true;
    new_fd->dir_ref = d;
    new_fd->file_ref = NULL;
  } else {
    /* Open as regular file FD. */
    struct file *f = file_open(inode);
    if (f == NULL) {
      inode_close(inode);
      free(new_fd);
      lock_release(&file_lock);
      return -1;
    }

    new_fd->is_dir  = false;
    new_fd->file_ref = f;
    new_fd->dir_ref  = NULL;
  }

  /* Add to the current thread's descriptor table (sets file_id). */
  add_fd_table_row(&cur->file_descriptor_table, new_fd);

  lock_release(&file_lock);
  return new_fd->file_id;
}

int filesize (int handle){
  struct thread *cur = thread_current();

  /* stdin/stdout/stderr do not have a meaningful size */
  if (handle == 0 || handle == 1 || handle == 2) { // Reserved values for default stdin, stdout, stderr
    return -1;
  }

  lock_acquire (&file_lock);
  struct file_descriptor *fd = lookup_fd(handle, &cur->file_descriptor_table);

  if (fd == NULL || fd->is_dir) {
    lock_release (&file_lock);
    return -1;
  }

  int len = file_length(fd->file_ref);
  lock_release (&file_lock);

  return len; // off_t file_length (struct file *);
}

int read (int fd, void *buffer, unsigned size) {

  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  if (buffer == NULL) exit(-1);
  if (size == 0) return 0;
  if (fd == STDOUT_FILENO) return -1;

  uint8_t *ubuf = (uint8_t *)buffer;

  /* Read from stdin. */
  if (fd == STDIN_FILENO) {
    for (unsigned i = 0; i < size; i++) {
      uint8_t c = (uint8_t) input_getc();
      if (!put_user(ubuf + i, c)) exit(-1);
    }
    return (int)size;
  }

  struct file_descriptor *fdn =
      lookup_fd(fd, &thread_current()->file_descriptor_table);

  /* Invalid FD or directory FD → cannot read. */
  if (!fdn || fdn->is_dir)
    return -1;

  int total = 0;
  uint8_t *kpage = palloc_get_page(0);
  if (!kpage) return -1;

  lock_acquire(&file_lock);
  while ((unsigned)total < size) {
    unsigned chunk = size - (unsigned)total;
    if (chunk > PGSIZE) chunk = PGSIZE;

    int n = file_read(fdn->file_ref, kpage, (int)chunk);
    if (n <= 0) break;

    for (int i = 0; i < n; i++) {
      if (!put_user(ubuf + total + i, kpage[i])) {
        lock_release(&file_lock);
        palloc_free_page(kpage);
        exit(-1);
      }
    }
    total += n;
  }
  lock_release(&file_lock);
  palloc_free_page(kpage);
  return total;
}

int write (int handle, const void *buffer, unsigned size){
  check_user((const uint8_t*) buffer);
  check_user((const uint8_t*) buffer + size - 1);

  struct thread *cur = thread_current();

  const void *orig_user_buf = buffer;
  buffer = user_to_kernel_vaddr (buffer);

  struct file_descriptor *fd = NULL;
  if (handle != STDOUT_FILENO) {
    fd = lookup_fd(handle, &cur->file_descriptor_table);
  }

  int sizeToWrite   = (int)size;
  int total_written = 0;
  int retval        = 0;

  /* For non-stdout: FD must exist and must not be a directory. */
  if (handle != STDOUT_FILENO && (fd == NULL || fd->is_dir)) {
    return -1;
  }

  if (sizeToWrite <= 0) {
    return 0;
  }

  int iter = 0;
  while (sizeToWrite > 0) {
    iter++;

    if (handle == STDOUT_FILENO) {
      putbuf (buffer, (size_t)sizeToWrite);
      retval        = sizeToWrite;
      total_written += retval;
      sizeToWrite   = 0;
      break;
    } else {
      retval = file_write (fd->file_ref, buffer, sizeToWrite);

      if (retval <= 0) {
        break;
      }

      total_written += retval;
      sizeToWrite   -= retval;
      buffer = (const uint8_t*)buffer + retval;
    }
  }

  return total_written;
}

void seek (int fd, unsigned position) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return;

  struct file_descriptor *fdn =
      lookup_fd(fd, &thread_current()->file_descriptor_table);
  if (!fdn || fdn->is_dir) return;

  lock_acquire(&file_lock);
  file_seek(fdn->file_ref, position);
  lock_release(&file_lock);
}

unsigned tell (int fd) {
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO) return 0;

  struct file_descriptor *fdn =
      lookup_fd(fd, &thread_current()->file_descriptor_table);
  if (!fdn || fdn->is_dir) return 0;

  lock_acquire(&file_lock);
  unsigned pos = file_tell(fdn->file_ref);
  lock_release(&file_lock);
  return pos;
}

void close (int fd) {
  struct thread *cur = thread_current();

  if (fd < 0) {
    return;
  }

  /* Don't close standard FDs (stdin=0, stdout=1, stderr=2). */
  if (fd == 0 || fd == 1 || fd == 2) {
    return;
  }

  struct file_descriptor *fd_desc = lookup_fd(fd, &cur->file_descriptor_table);
  if (fd_desc == NULL) {
    return;
  }

  lock_acquire(&file_lock);

  if (fd_desc->is_dir) {
    /* Directory FD */
    if (fd_desc->dir_ref != NULL) {
      dir_close(fd_desc->dir_ref);
      fd_desc->dir_ref = NULL;
    }
  } else {
    /* Regular file FD */
    if (fd_desc->file_ref != NULL) {
      file_close(fd_desc->file_ref);
      fd_desc->file_ref = NULL;
    }
  }

  lock_release(&file_lock);

  struct file_descriptor *removed =
      remove_fd_table_row(&cur->file_descriptor_table, fd_desc);

  if (removed != NULL) {
    free(removed);
  }
}

bool chdir (const char *dir) {
  /* Validate user pointer and translate to kernel addr. */
  check_user((const uint8_t *) dir);
  dir = user_to_kernel_vaddr((void *) dir);

  bool success = false;
  lock_acquire(&file_lock);
  success = filesys_chdir(dir);
  lock_release(&file_lock);

  return success;
}

bool mkdir (const char *dir) {
  /* Validate user pointer and translate to kernel addr. */
  check_user((const uint8_t *) dir);
  dir = user_to_kernel_vaddr((void *) dir);

  bool success = false;

  lock_acquire(&file_lock);
  /* Create a directory inode (size 0 is fine; dir layer handles entries). */
  success = filesys_create(dir, 0, DIR_INODE);
  lock_release(&file_lock);

  return success;
}

bool readdir (int fd, char *name) {
  struct thread *cur = thread_current();

  /* Validate user buffer: we’ll write up to NAME_MAX+1 bytes. */
  validate_user_writable_range(name, NAME_MAX + 1);

  char *kname = user_to_kernel_vaddr((void *) name);

  struct file_descriptor *fdn =
      lookup_fd(fd, &cur->file_descriptor_table);

  if (fdn == NULL || !fdn->is_dir) {
    return false;
  }

  bool success = false;
  lock_acquire(&file_lock);
  success = dir_readdir(fdn->dir_ref, kname);
  lock_release(&file_lock);

  return success;
}

bool isdir (int fd) {
  struct thread *cur = thread_current();
  struct file_descriptor *fdn =
      lookup_fd(fd, &cur->file_descriptor_table);

  if (fdn == NULL) {
    return false;
  }

  return fdn->is_dir;
}

int inumber (int fd) {
  struct thread *cur = thread_current();
  struct file_descriptor *fdn =
      lookup_fd(fd, &cur->file_descriptor_table);

  if (fdn == NULL) {
    return -1;
  }

  struct inode *inode = NULL;

  if (fdn->is_dir) {
    if (fdn->dir_ref == NULL) return -1;
    inode = dir_get_inode(fdn->dir_ref);
  } else {
    if (fdn->file_ref == NULL) return -1;
    inode = file_get_inode(fdn->file_ref);
  }

  if (inode == NULL) {
    return -1;
  }

  return (int) inode_get_inumber(inode);
}
////////////////////////////////////////////////////////////////////////////////
//                              Helper Functions
////////////////////////////////////////////////////////////////////////////////

static void
check_user (const uint8_t *uaddr) {
  if(get_user (uaddr) == -1)
    fail_invalid_access();
}

static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static int
copy_bytes(void *from, void *to, size_t byte_count) {
  if (from == NULL || to == NULL) {
    fail_invalid_access();
    return -1;
  }

  size_t i;
  int value;

  for (i = 0; i < byte_count; i++) {
    uint8_t *src = (uint8_t *)from + i;
    uint8_t *dst = (uint8_t *)to   + i;

    value = get_user(src);
    if (value == -1) {
      fail_invalid_access();
    }

    *(char*)dst = (char)(value & 0xff);
  }

  return (int) byte_count;
}

static void *
user_to_kernel_vaddr (void *uaddr) {
  struct thread *t = thread_current ();
  void *kaddr = NULL;
  if(is_user_vaddr(uaddr))
    kaddr = pagedir_get_page (t->pagedir, uaddr);
  if (kaddr == NULL)
    exit (-1);
  return kaddr;
}

static void fail_invalid_access(void) {
  exit (-1);
  NOT_REACHED();
}

static void validate_user_readable_range (const void *uaddr, unsigned size) {
  if (size == 0) return;
  const uint8_t *start = uaddr, *end = start + size - 1;
  struct thread *t = thread_current();
  for (const uint8_t *p = start; ; ) {
    if (!is_user_vaddr(p) || pagedir_get_page(t->pagedir, (void*)p) == NULL) exit(-1);
    int b = get_user(p);       /* fault-safe read probe */
    if (b == -1) exit(-1);

    if (p >= end) break;
    uintptr_t next = ((uintptr_t)p & ~PGMASK) + PGSIZE;
    p = (next > (uintptr_t)end) ? end : (const uint8_t*)next;
  }
}

static void validate_user_writable_range (void *uaddr, unsigned size) {
  if (size == 0) return;
  uint8_t *start = uaddr, *end = start + size - 1;
  struct thread *t = thread_current();
  for (uint8_t *p = start; ; ) {
    if (!is_user_vaddr(p) || pagedir_get_page(t->pagedir, p) == NULL) exit(-1);
    int b = get_user(p);
    if (b == -1) exit(-1);
    if (!put_user(p, (uint8_t)b)) exit(-1);  /* write probe */

    if (p >= end) break;
    uintptr_t next = ((uintptr_t)p & ~PGMASK) + PGSIZE;
    p = (next > (uintptr_t)end) ? end : (uint8_t*)next;
  }
}

////////////////////////////////////////////////////////////////////////////////
//                          File Description Handlers
////////////////////////////////////////////////////////////////////////////////

bool cmp_fd_id (const struct list_elem *a, const struct list_elem *b, void *aux) {
  const struct file_descriptor *f_a = list_entry(a, struct file_descriptor, elem);
  const struct file_descriptor *f_b = list_entry(b, struct file_descriptor, elem);
  return f_a->file_id < f_b->file_id;
}

struct file_descriptor* lookup_fd(int id, struct list *fd_table){
  struct list_elem *e;
      
  for (e = list_begin (fd_table); e != list_end (fd_table); e = list_next (e)){
    struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
    if(fd->file_id == id){
      return fd;
    }
  }

  return NULL;
}

void add_fd_table_row(struct list *fd_table, struct file_descriptor *new_element){
  if (list_size(fd_table) == 0) {
    new_element->file_id = 3;
  } else {
    int next_expected_id = 3;
    bool found_gap = false;
    struct list_elem *e;

    int file_id = -1;

    for (e = list_begin(fd_table);
         e != list_end(fd_table);
         e = list_next(e)) {
      struct file_descriptor *current_fd = list_entry(e, struct file_descriptor, elem);
      if (current_fd->file_id == next_expected_id) {
        next_expected_id++;
      } else if (current_fd->file_id > next_expected_id) {
        found_gap = true;
        break;
      }
    }

    new_element->file_id = next_expected_id;
  }
  list_insert_ordered(fd_table, &new_element->elem, cmp_fd_id, NULL);
}

struct file_descriptor *
remove_fd_table_row (struct list *fd_table, struct file_descriptor *fd)
{
  if (fd_table == NULL || fd == NULL)
    return NULL;

  if (fd->file_id >= 0 && fd->file_id <= 2)
    return NULL;

  struct list_elem *e;
  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    if (e == &fd->elem) {
      list_remove(e);
      return fd;
    }
  }

  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    struct file_descriptor *cur = list_entry(e, struct file_descriptor, elem);
    if (cur->file_id == fd->file_id) {
      list_remove(&cur->elem);
      return cur;
    }
  }

  return NULL;
}