# PintOS

PintOS is a teaching operating system for x86 architecture, originally developed at Stanford University. This repository contains a working implementation with three of the four major project milestones completed: **Threads**, **User Programs**, and **File Systems**. The Virtual Memory project is stubbed but not implemented.

## Project Structure

```
src/
├── threads/       Core kernel: threading, scheduling, synchronization, memory allocation
├── userprog/      User program loading, system call handling, process management
├── vm/            Virtual memory (stubs only — not implemented)
├── filesys/       File system with indexed inodes and subdirectory support
├── devices/       Hardware drivers (timer, keyboard, disk, serial, VGA)
├── lib/           Shared C library used by both kernel and user programs
├── examples/      Example user programs (cat, cp, echo, ls, mkdir, shell, etc.)
├── tests/         Perl-based test suite with expected-output checks
├── utils/         Build utilities (pintos runner, mkdisk, etc.)
└── misc/          Miscellaneous helper scripts
```

## What Is Implemented

### Project 1 — Threads

The kernel threading system in `src/threads/` provides:

- **Thread lifecycle**: creation, scheduling, context switching, and destruction.
- **Priority-based scheduling** with round-robin time slicing (4-tick quantum).
- **Multi-level feedback queue scheduler (MLFQS)** support as an alternative scheduler.
- **Synchronization primitives**: semaphores, locks, and condition variables (`synch.c`).
- **Memory allocators**: a page allocator (`palloc.c`) for 4 KB pages and a sub-page malloc allocator (`malloc.c`).

### Project 2 — User Programs

User program support lives in `src/userprog/` and includes:

- **ELF binary loading** with full command-line argument passing. Arguments are placed on the user stack following x86 calling conventions (`process.c`).
- **15 system calls** implemented in `syscall.c`:

  | Syscall | Description |
  |---------|-------------|
  | `halt` | Shut down the machine |
  | `exit` | Terminate the current process with a status code |
  | `exec` | Start a new process from an executable path |
  | `wait` | Block until a child process exits |
  | `create` | Create a new file of a given size |
  | `remove` | Delete a file by name |
  | `open` | Open a file and return a file descriptor |
  | `filesize` | Return the size of an open file |
  | `read` | Read bytes from a file descriptor (or stdin) |
  | `write` | Write bytes to a file descriptor (or stdout) |
  | `seek` | Set the read/write position of a file |
  | `tell` | Return the current position of a file |
  | `close` | Close a file descriptor |
  | `chdir` | Change the current working directory |
  | `mkdir` | Create a new directory |

  Additional directory-related syscalls (`readdir`, `isdir`, `inumber`) are also present.

- **Per-process file descriptor table** with descriptors 0, 1, and 2 reserved for stdin, stdout, and stderr.
- **Parent-child process management**: the parent tracks each child via a `child_process` struct and synchronizes on load and exit using semaphores.
- **User memory validation**: every pointer passed from user space is checked before access; invalid pointers cause the process to exit with status `-1`.

### Project 3 — Virtual Memory (Not Implemented)

The `src/vm/` directory contains stub files (`page.c`, `frame.c`, `swap.c`). The thread struct has a `page_hash` field for a supplemental page table, but no demand paging, swapping, or memory-mapped files are implemented.

### Project 4 — File Systems

The file system in `src/filesys/` goes well beyond the default PintOS flat file system:

- **Multi-level indexed inodes** (`inode.c`): each inode has 12 direct blocks, 1 single-indirect block (128 pointers), and 1 double-indirect block (128 x 128 pointers), giving a maximum file size of roughly 8 MB.
- **Subdirectory support** (`directory.c`, `filesys.c`): full path resolution for both absolute (`/a/b/c`) and relative paths, resolved from the process's current working directory.
- **Per-process current working directory**: inherited from parent to child on `exec`.
- **Directory operations**: create, remove, list entries, and traverse.
- **Write-deny semantics**: running executables cannot be modified while in use, enforced through deny-write counters and condition variables on inodes.

## Synchronization Design

- A **global `file_lock`** serializes all file system operations from user space. This is simple but limits concurrency.
- **Per-inode locks** protect inode metadata during read/write and extension.
- **Semaphores** are used for parent-child signaling (load success/failure and exit status).
- **Condition variables** coordinate deny-write tracking on inodes.

## Building

PintOS requires an **i386-elf cross-compiler toolchain** (`i386-elf-gcc`, `i386-elf-ld`, etc.) and standard Unix build tools.

To build a specific project:

```bash
cd src/userprog   # or src/threads, src/filesys
make
```

This produces a `build/` directory containing `kernel.bin`, `kernel.o`, and the bootable `os.dsk` disk image.

### User Programs

Example user programs in `src/examples/` (cat, cp, echo, ls, mkdir, shell, etc.) are compiled automatically during the `userprog` or `filesys` build.

## Running

PintOS can run on QEMU or Bochs. The `pintos` utility script in `src/utils/` wraps the emulator invocation:

```bash
cd src/userprog/build
pintos -- run 'echo hello world'
```

To run with a file system disk:

```bash
pintos -p ../../examples/echo -a echo -- -f -q run 'echo hello world'
```

- `-p <file> -a <name>`: copies a file into the PintOS file system under the given name.
- `-f`: formats the file system before running.
- `-q`: powers off after the command finishes.

## Testing

Each project has a test suite under `src/tests/`. Tests are Perl scripts that compare actual kernel output against expected output (`.ck` files).

```bash
cd src/userprog/build
make check          # run all tests for this project
make tests/userprog/args-none.result   # run a single test
```

Test categories include:
- **threads**: alarm, priority donation, MLFQS scheduling
- **userprog**: argument passing, system calls, bad pointer handling, multi-process scenarios
- **filesys**: basic file operations, extended indexed-inode tests, directory tests

## Architecture Overview

```
┌──────────────────────────────────────────────┐
│              User Programs                   │
│         (examples/: cat, ls, shell)          │
├──────────────────────────────────────────────┤
│            System Call Interface             │
│              (userprog/syscall.c)            │
├────────────┬─────────────┬───────────────────┤
│  Process   │  File       │  Directory        │
│  Mgmt      │  Operations │  Operations       │
│ (process.c)│ (file.c)    │ (directory.c)     │
├────────────┴─────────────┴───────────────────┤
│             File System Layer                │
│    (filesys.c, inode.c, free-map.c)          │
├──────────────────────────────────────────────┤
│             Block Device Layer               │
│          (devices/block.c, ide.c)            │
├──────────────────────────────────────────────┤
│          Kernel Threading & Memory           │
│  (threads/thread.c, synch.c, palloc.c)       │
├──────────────────────────────────────────────┤
│        x86 Hardware (via QEMU/Bochs)         │
└──────────────────────────────────────────────┘
```

## Memory Layout

- **User space**: `0x00000000` — `0xC0000000` (lower 3 GB)
- **Kernel space**: `0xC0000000` — `0xFFFFFFFF` (upper 1 GB)
- **Page size**: 4096 bytes
- **Disk sector size**: 512 bytes

## Key Files

| File | Purpose |
|------|---------|
| `threads/thread.c` | Thread creation, scheduling, context switching |
| `threads/synch.c` | Semaphores, locks, condition variables |
| `userprog/process.c` | Process loading, argument setup, wait/exit |
| `userprog/syscall.c` | System call dispatch and implementation |
| `userprog/pagedir.c` | Page directory management for user processes |
| `filesys/inode.c` | On-disk inode with multi-level indexing |
| `filesys/filesys.c` | High-level file system operations and path resolution |
| `filesys/directory.c` | Directory entry management |
| `devices/timer.c` | System timer and tick counting |
| `devices/ide.c` | IDE disk controller driver |

## Limitations

- **No virtual memory**: pages are never swapped to disk; processes are limited to physical memory.
- **Single-threaded processes**: each process has exactly one kernel thread.
- **Coarse-grained file system locking**: a single global lock serializes all file operations.
- **Max file size ~8 MB**: constrained by the double-indirect block indexing scheme.
- **Max filename length**: 14 characters per path component.
