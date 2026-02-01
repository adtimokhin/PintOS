#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

// NOTE: 
// - Most of the modifications for large files
//      will be around inode.h and inode.c
// - A poorly implemented inode will affect the 
//      correctness of all P4 functionalities
// - Changes to the inode must be written back to 
//      its on-disk representation (inode_disk) to maintain consistency.
//      So, use on-disk inode as single source of truth

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INODE_MEM_MAGIC 0xC0FFEE01u

#define DIRECT_CNT 12
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)

/* 
  On-disk inode.
  Must be exactly BLOCK_SECTOR_SIZE bytes long. 
   
  In our case, BLOCK_SECTOR_SIZE = 512 bytes
*/
struct inode_disk
  {
    block_sector_t sectors[SECTOR_CNT]; /* Sectors. */
    enum inode_type type;               /* FILE_INODE or DIR_INODE. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    // Indixes
    uint32_t direct_index;              /* Current index of direct block */
    uint32_t indirect_index;            /* Current index of indirect block */
    uint32_t dbl_indirect_index;        /* Current index of double indirect block */
    // Unused
    uint32_t unused[108];               /* Unused data */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    struct lock lock;                   /* Protects the inode. */

    /* Denying writes. */
    struct lock deny_write_lock;        /* Protects members below. */
    struct condition no_writers_cond;   /* Signaled when no writers. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    int writer_cnt;                     /* Number of writers. */

    /* Debugging: detect bogus inode pointers. */
    unsigned mem_magic;
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list. */
static struct lock open_inodes_lock;

static void deallocate_inode (const struct inode *);
static void inode_mark_valid (struct inode *inode);
static void inode_assert_valid (const char *who, const struct inode *inode);
static void inode_assert_sector_valid (const char *who, block_sector_t sector);

////////////////////////////////////////////////////////////////////////////////
//                          DEBUG STATIC ROUTINES
////////////////////////////////////////////////////////////////////////////////
/* Marks an in-memory inode as valid. Must be called exactly once
   after fully initializing the inode struct. */
static void
inode_mark_valid (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->mem_magic = INODE_MEM_MAGIC;
}

/* Asserts that INODE is a valid in-memory inode and that its sector
   is at least plausible. This helps catch cases where a random pointer
   is accidentally treated as a struct inode*. */
static void
inode_assert_valid (const char *who, const struct inode *inode)
{
  ASSERT (inode != NULL);

  if (inode->mem_magic != INODE_MEM_MAGIC)
    {
    // debug
// debug
// printf ("%s: FATAL - inode %p has invalid mem_magic=0x%X " "(expected 0x%X)\n", who, inode, inode->mem_magic, INODE_MEM_MAGIC);
      PANIC ("inode_assert_valid: invalid struct inode pointer");
    }

  inode_assert_sector_valid (who, inode->sector);
}

/* Asserts that SECTOR is within the bounds of fs_device. */
static void
inode_assert_sector_valid (const char *who, block_sector_t sector)
{
  /* fs_device is set up in filesys_init(). Be defensive in early boot. */
  if (fs_device == NULL)
    return;

  block_sector_t limit = block_size (fs_device);
  if (sector >= limit)
    {
    // debug
// debug
// printf ("%s: FATAL - sector %u out of range (block_size=%u)\n",  who, sector, limit);
      PANIC ("inode_assert_sector_valid: sector out of range");
    }
}

////////////////////////////////////////////////////////////////////////////////
//                             INODE METHODS
////////////////////////////////////////////////////////////////////////////////
/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);

  // debug
// debug
// debug
// printf ("inode_init: open_inodes_lock at %p\n", (void *) &open_inodes_lock);
 // debug
// debug
// debug
// printf ("inode_init: &open_inodes.head=%p, &open_inodes.tail=%p\n", (void *) &open_inodes.head, (void *) &open_inodes.tail);
 // debug
// debug
// debug
// printf ("inode_init: open_inodes_lock at %p\n", (void *) &open_inodes_lock);
}

/* Initializes an inode of the given TYPE, writes the new inode
   to sector SECTOR on the file system device, and returns the
   inode thus created.  Returns a null pointer if unsuccessful,
   in which case SECTOR is released in the free map. */
struct inode *
inode_create (block_sector_t sector, enum inode_type type)
{

  // debug
// debug
// debug
// printf("=== inode_create START ===\n");
  // debug
// debug
// debug
// printf("inode_create: sector = %u, type = %d (%s)\n", sector, type, type == FILE_INODE ? "FILE" : "DIR");

  struct inode_disk *disk_inode = NULL;
  struct inode *inode = NULL;

  // debug
// debug
// debug
// printf("sizeof *disk_inode == %d\n", sizeof *disk_inode);
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return NULL;

  // If all good - set default values for the disk_inode and make an inode
  disk_inode->type = type;
  disk_inode->length = 0;
  disk_inode->magic = INODE_MAGIC;
  disk_inode->direct_index = 0;
  disk_inode->indirect_index = 0;
  disk_inode->dbl_indirect_index = 0;

  // debug
// debug
// debug
// printf("inode_create: disk_inode fields: length=%d, magic=0x%X, type=%d\n", disk_inode->length, disk_inode->magic, disk_inode->type);
  // debug
// debug
// debug
// printf("inode_create: disk_inode indices: direct=%u, indirect=%u, dbl_indirect=%u\n", disk_inode->direct_index, disk_inode->indirect_index,  disk_inode->dbl_indirect_index);

  // debug
// debug
// debug
// printf("inode_create: Writing disk_inode to sector %u...\n", sector);
  block_write (fs_device, sector, disk_inode);
  // debug
// debug
// debug
// printf("inode_create: disk_inode successfully written to disk\n");

  /* Now allocate and initialize the in-memory inode */
  // debug
// debug
// debug
// printf("inode_create: Allocating in-memory inode structure...\n");
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    {
      // debug
// debug
// debug
// printf("inode_create: ERROR - Failed to allocate in-memory inode\n");
      free (disk_inode);
      free_map_release (sector);
      // debug
// debug
// debug
// printf("inode_create: Released sector %u back to free map\n", sector);
      // debug
// debug
// debug
// printf("=== inode_create END (FAILURE) ===\n");
      return NULL;
    }
  // debug
// debug
// debug
// printf("inode_create: in-memory inode allocated at %p\n", inode);

  // TODO: Initiate all sectors to 0 or something like that
  
  /* Initialize in-memory inode fields */
  // debug
// debug
// debug
// printf("inode_create: Initializing in-memory inode fields...\n");
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->removed = false;
  inode->deny_write_cnt = 0;
  inode->writer_cnt = 0;

  // debug
// debug
// debug
// printf("inode_create: Initializing inode locks and condition variables...\n");
  lock_init (&inode->lock);
  lock_init (&inode->deny_write_lock);
  cond_init (&inode->no_writers_cond);
  // debug
// debug
// debug
// printf("inode_create: Locks and condition variables initialized\n");

  // debug
// debug
// debug
// printf ("inode_create: inode=%p, &inode->lock=%p, &inode->deny_write_lock=%p\n", inode, &inode->lock, &inode->deny_write_lock);

  /* Add to open inodes list */

  /* Mark as valid for debug/sanity. */
  inode_mark_valid (inode);

  // debug
// debug
// debug
// printf("inode_create: Adding inode to open_inodes list...\n");
  lock_acquire (&open_inodes_lock);
  list_push_front (&open_inodes, &inode->elem);
  lock_release (&open_inodes_lock);
  // debug
// debug
// debug
// printf("inode_create: Inode added to open_inodes list\n");

  // debug
// debug
// debug
// printf("inode_create: Final inode state:\n");
  // debug
// debug
// debug
// printf("  - sector: %u\n", inode->sector);
  // debug
// debug
// debug
// printf("  - open_cnt: %d\n", inode->open_cnt);
  // debug
// debug
// debug
// printf("  - removed: %s\n", inode->removed ? "true" : "false");
  // debug
// debug
// debug
// printf("  - deny_write_cnt: %d\n", inode->deny_write_cnt);
  // debug
// debug
// debug
// printf("  - writer_cnt: %d\n", inode->writer_cnt);

  /* Clean up disk inode (no longer needed) */
  free (disk_inode);
  // debug
// debug
// debug
// printf("inode_create: disk_inode freed\n");

  // debug
// debug
// debug
// printf("=== inode_create END (SUCCESS) ===\n");
  return inode;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  // Don't forget to access open_inodes list
  // debug
// debug
// debug
// printf("=== inode_open START ===\n");
  // debug
// debug
// debug
// printf("inode_open: sector = %u\n", sector);
  
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  // debug
// debug
// debug
// printf("inode_open: Checking if inode is already in open_inodes list...\n");
  lock_acquire (&open_inodes_lock);

  int count = 0;
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      count++;
      inode = list_entry (e, struct inode, elem);
      
      // debug
      inode_assert_valid ("inode_open(scan)", inode);
      inode_assert_sector_valid ("inode_open(scan)", inode->sector);
      // debug
// debug
// debug
// printf("inode_open: Checking open inode #%d: sector=%u\n", count, inode->sector);
      
      if (inode->sector == sector)
        {
          // debug
// debug
// debug
// printf("inode_open: Found existing inode for sector %u!\n", sector);
          // debug
// debug
// debug
// printf("inode_open: Current open_cnt = %d\n", inode->open_cnt);
          inode->open_cnt++;
          // debug
// debug
// debug
// printf("inode_open: Incremented open_cnt to %d\n", inode->open_cnt);
          lock_release (&open_inodes_lock);
          // debug
// debug
// debug
// printf("=== inode_open END (REOPEN) ===\n");
          return inode;
        }
    }

  // debug
// debug
// debug
// printf("inode_open: Inode not found in open_inodes (checked %d entries)\n", count);
  lock_release (&open_inodes_lock);
  
  /* Allocate memory for new inode. */
  // debug
// debug
// debug
// printf("inode_open: Allocating new inode structure...\n");
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    {
      // debug
// debug
// debug
// printf("inode_open: ERROR - Failed to allocate memory for inode\n");
      // debug
// debug
// debug
// printf("=== inode_open END (FAILURE) ===\n");
      return NULL;
    }
  
  // debug
// debug
// debug
// printf("inode_open: inode allocated at %p\n", inode);

  /* Initialize inode fields. */
  // debug
// debug
// debug
// printf("inode_open: Initializing inode fields...\n");
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->writer_cnt = 0;
  inode->removed = false;

  // debug
// debug
// debug
// printf("inode_open: Initializing locks and condition variables...\n");
  lock_init (&inode->lock);
  lock_init (&inode->deny_write_lock);
  cond_init (&inode->no_writers_cond);
  
  // debug
// debug
// debug
// printf("inode_open: inode fields initialized:\n");
  // debug
// debug
// debug
// printf("  - sector: %u\n", inode->sector);
  // debug
// debug
// debug
// printf("  - open_cnt: %d\n", inode->open_cnt);
  // debug
// debug
// debug
// printf("  - deny_write_cnt: %d\n", inode->deny_write_cnt);
  // debug
// debug
// debug
// printf("  - writer_cnt: %d\n", inode->writer_cnt);
  // debug
// debug
// debug
// printf("  - removed: %s\n", inode->removed ? "true" : "false");

  /* Verify inode exists on disk by reading its disk structure */
  // debug
// debug
// debug
// printf("inode_open: Reading inode_disk from sector %u to verify...\n", sector);
  struct inode_disk disk_inode;
  block_read (fs_device, inode->sector, &disk_inode);

  // debug
// debug
// debug
// printf("inode_open: Disk inode data:\n");
  // debug
// debug
// debug
// printf("  - magic: 0x%X (expected: 0x%X)\n", disk_inode.magic, INODE_MAGIC);
  // debug
// debug
// debug
// printf("  - length: %d bytes\n", disk_inode.length);
  // debug
// debug
// debug
// printf("  - type: %d\n", disk_inode.type);
  // debug
// debug
// debug
// printf("  - direct_index: %u\n", disk_inode.direct_index);
  // debug
// debug
// debug
// printf("  - indirect_index: %u\n", disk_inode.indirect_index);
  // debug
// debug
// debug
// printf("  - dbl_indirect_index: %u\n", disk_inode.dbl_indirect_index);

  /* Sanity check: verify magic number */
  if (disk_inode.magic != INODE_MAGIC)
    {
      // debug
// debug
// debug
// printf("inode_open: WARNING - Invalid magic number! This may not be a valid inode.\n");
    }
  
  /* Add to open inodes list. */
  // debug
// debug
// debug
// printf("inode_open: Adding inode to open_inodes list...\n");

  inode_mark_valid (inode);
  inode_assert_valid ("inode_open(new)", inode);

  lock_acquire (&open_inodes_lock);
  list_push_front (&open_inodes, &inode->elem);
  lock_release (&open_inodes_lock);
  // debug
// debug
// debug
// printf("inode_open: Successfully added to open_inodes list\n");

  // debug
// debug
// debug
// printf("=== inode_open END (SUCCESS - NEW OPEN) ===\n");
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      lock_acquire (&open_inodes_lock);
      inode_assert_valid ("inode_reopen", inode);
      inode->open_cnt++;
      lock_release (&open_inodes_lock);
    }
  return inode;
}

/* Returns the type of INODE. */
enum inode_type
inode_get_type (const struct inode *inode)
{
  ASSERT (inode != NULL);
  
  // debug
// debug
// debug
// printf("inode_get_type: Called for inode at %p, sector %u\n",  inode, inode->sector);
  
  /* Allocate temporary buffer for disk inode */
  struct inode_disk *disk_inode = malloc (sizeof *disk_inode);
  if (disk_inode == NULL)
    {
      // debug
// debug
// debug
// printf("inode_get_type: ERROR - Failed to allocate disk_inode buffer\n");
      PANIC ("inode_get_type: malloc failed");
    }
  
  /* Read inode data from disk */
  // debug
// debug
// debug
// printf("inode_get_type: Reading inode_disk from sector %u...\n", inode->sector);
  inode_assert_sector_valid ("inode_get_type/read", inode->sector);
  block_read (fs_device, inode->sector, disk_inode);
  
  /* Verify magic number */
  if (disk_inode->magic != INODE_MAGIC)
    {
      // debug
// debug
// debug
// printf("inode_get_type: WARNING - Invalid magic number 0x%X (expected 0x%X)\n", disk_inode->magic, INODE_MAGIC);
    }
  
  /* Get the type */
  enum inode_type type = disk_inode->type;
  
  // debug
// debug
// debug
// printf("inode_get_type: Type = %d (%s)\n", type, type == FILE_INODE ? "FILE_INODE" : "DIR_INODE");
  // debug
// debug
// debug
// printf("inode_get_type: Additional info - length=%d, direct_index=%u\n", disk_inode->length, disk_inode->direct_index);
  
  /* Free temporary buffer */
  free (disk_inode);
  // debug
// debug
// debug
// printf("inode_get_type: Returning type %d\n", type);
  
  return type;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  // debug
// debug
// debug
// printf("=== inode_close START ===\n");

  /* Ignore null pointer. */
  if (inode == NULL)
    {
      // debug
// debug
// debug
// printf("inode_close: inode is NULL, nothing to do\n");
      // debug
// debug
// debug
// printf("=== inode_close END (NULL) ===\n");
      return;
    }

  // debug
// debug
// debug
// printf("inode_close: inode=%p, sector=%u\n", (void *) inode, inode->sector);

  /* Release resources if this was the last opener. */
  lock_acquire (&open_inodes_lock);

  ASSERT (inode->open_cnt > 0);
  // debug
// debug
// debug
// printf("inode_close: current open_cnt=%d\n", inode->open_cnt);

  inode->open_cnt--;
  // debug
// debug
// debug
// printf("inode_close: decremented open_cnt to %d\n", inode->open_cnt);

  if (inode->open_cnt > 0)
    {
      /* Still open somewhere else, just drop our ref. */
      lock_release (&open_inodes_lock);
      // debug
// debug
// debug
// printf("inode_close: inode still has openers, not freeing\n");
      // debug
// debug
// debug
// printf("=== inode_close END (STILL OPEN) ===\n");
      return;
    }

  /* This was the last opener. Remove from global list. */
  // debug
// debug
// debug
// printf("inode_close: last opener, removing from open_inodes list\n");
  list_remove (&inode->elem);
  lock_release (&open_inodes_lock);

  // debug
// debug
// debug
// printf("inode_close: removed flag=%s\n", inode->removed ? "true" : "false");

  if (inode->removed)
    {
      /* Deallocate all data blocks and then the inode sector itself. */
      // debug
// debug
// debug
// printf("inode_close: inode marked removed, deallocating its blocks\n");
      deallocate_inode (inode);

      // debug
// debug
// debug
// printf("inode_close: releasing inode sector %u back to free map\n", inode->sector);
      free_map_release (inode->sector);
    }
  else
    {
      /* In your current design, all metadata (length, block pointers, etc.)
         is already kept on disk and updated by extend_file/get_data_block.
         There is nothing extra cached in struct inode to flush here. */

      // debug
// debug
// debug
// printf("inode_close: inode not removed, no block deallocation needed\n");

      /* Optional sanity read / debug (can be removed later): */
      struct inode_disk disk_inode;
      block_read (fs_device, inode->sector, &disk_inode);
      // debug
// debug
// debug
// printf("inode_close: on-disk inode summary before free:\n");
      // debug
// debug
// debug
// printf("  - length=%d\n", disk_inode.length);
      // debug
// debug
// debug
// printf("  - magic=0x%X\n", disk_inode.magic);
      // debug
// debug
// debug
// printf("  - type=%d\n", disk_inode.type);
      // debug
// debug
// debug
// printf("  - direct_index=%u, indirect_index=%u, dbl_indirect_index=%u\n", disk_inode.direct_index, disk_inode.indirect_index, disk_inode.dbl_indirect_index);
    }

  // debug
// debug
// debug
// printf("inode_close: freeing in-memory inode at %p\n", (void *) inode);
  free (inode);

  // debug
// debug
// debug
// printf("=== inode_close END (FREED) ===\n");
}

/* Deallocates SECTOR and anything it points to recursively.
   LEVEL is 2 if SECTOR is doubly indirect,
   or 1 if SECTOR is indirect,
   or 0 if SECTOR is a data sector. */
static void
deallocate_recursive (block_sector_t sector, int level)
{
  // debug
// debug
// debug
// printf("=== deallocate_recursive START ===\n");
  // debug
// debug
// debug
// printf("deallocate_recursive: sector=%u, level=%d\n", sector, level);

  if (sector == 0)
    {
      // debug
// debug
// debug
// printf("deallocate_recursive: sector is 0 (unused), nothing to free\n");
      // debug
// debug
// debug
// printf("=== deallocate_recursive END (NOOP) ===\n");
      return;
    }

  if (level == 0)
    {
      /* Data block. */
      // debug
// debug
// debug
// printf("deallocate_recursive: freeing data block sector %u\n", sector);
      free_map_release (sector);
      // debug
// debug
// debug
// printf("=== deallocate_recursive END (DATA) ===\n");
      return;
    }

  /* level > 0 – sector is an indirect or double-indirect block. */
  block_sector_t ptrs[PTRS_PER_SECTOR];
  // debug
// debug
// debug
// printf("deallocate_recursive: reading pointer block from sector %u\n", sector);
  block_read (fs_device, sector, ptrs);

  for (size_t i = 0; i < PTRS_PER_SECTOR; i++)
    {
      if (ptrs[i] != 0)
        {
          // debug
// debug
// debug
// printf("deallocate_recursive: entry[%zu] -> sector %u (recurse level %d)\n", i, ptrs[i], level - 1);
          deallocate_recursive (ptrs[i], level - 1);
        }
    }

  // debug
// debug
// debug
// printf("deallocate_recursive: freeing pointer block sector %u (level=%d)\n", sector, level);
  free_map_release (sector);

  // debug
// debug
// debug
// printf("=== deallocate_recursive END (INDIRECT LEVEL %d) ===\n", level);
}


/* Deallocates the blocks allocated for INODE. */
static void
deallocate_inode (const struct inode *inode)
{
  // debug
// debug
// debug
// printf("=== deallocate_inode START ===\n");
  ASSERT (inode != NULL);

  // debug
// debug
// debug
// printf("deallocate_inode: inode=%p, sector=%u\n", (void *) inode, inode->sector);

  struct inode_disk disk_inode;
  // debug
// debug
// debug
// printf("deallocate_inode: reading inode_disk from sector %u\n", inode->sector);
  block_read (fs_device, inode->sector, &disk_inode);

  // debug
// debug
// debug
// printf("deallocate_inode: disk_inode info:\n");
  // debug
// debug
// debug
// printf("  - length=%d\n", disk_inode.length);
  // debug
// debug
// debug
// printf("  - magic=0x%X\n", disk_inode.magic);
  // debug
// debug
// debug
// printf("  - type=%d\n", disk_inode.type);

  /* Free direct blocks. */
  for (size_t i = 0; i < DIRECT_CNT; i++)
    {
      block_sector_t s = disk_inode.sectors[i];
      if (s != 0)
        {
          // debug
// debug
// debug
// printf("deallocate_inode: freeing direct block #%zu at sector %u\n", i, s);
          free_map_release (s);
        }
      else
        {
         
             // debug
// debug
// debug
// printf("deallocate_inode: direct block #%zu is 0 (unused)\n", i);
         
        }
    }

  /* Single-indirect root. */
  block_sector_t indirect_root = disk_inode.sectors[DIRECT_CNT];
  if (indirect_root != 0)
    {
      // debug
// debug
// debug
// printf("deallocate_inode: freeing single-indirect tree rooted at sector %u\n", indirect_root);
      deallocate_recursive (indirect_root, 1);
    }
  else
    {
      // debug
// debug
// debug
// printf("deallocate_inode: no single-indirect root (sector is 0)\n");
    }

  /* Double-indirect root. */
  block_sector_t dbl_root = disk_inode.sectors[DIRECT_CNT + INDIRECT_CNT];
  if (dbl_root != 0)
    {
      // debug
// debug
// debug
// printf("deallocate_inode: freeing double-indirect tree rooted at sector %u\n", dbl_root);
      deallocate_recursive (dbl_root, 2);
    }
  else
    {
      // debug
// debug
// debug
// printf("deallocate_inode: no double-indirect root (sector is 0)\n");
    }

  // debug
// debug
// debug
// printf("=== deallocate_inode END ===\n");
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}


////////////////////////////////////////////////////////////////////////////////
//                              HELPERS
////////////////////////////////////////////////////////////////////////////////

/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets. 
   offset_cnt can be 1 to 3 depending on whether sector_idx 
   points to sectors within DIRECT, INDIRECT, or DBL_INDIRECT ranges.
*/
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  ASSERT (sector_idx >= 0);
  /* Handle direct blocks. When sector_idx < DIRECT_CNT */
  // offset_cnt = 1, and offsets[0] = sector_idx
  if (sector_idx < DIRECT_CNT)
  {
    *offset_cnt = 1;
    offsets[0] = (size_t) sector_idx;
    return;
  }

  /* Handle indirect blocks. */
  // offset_cnt = 2, offsets[0] = DIRECT_CNT, offsets[1] ...
  sector_idx -= DIRECT_CNT;
  if (sector_idx < (off_t) (PTRS_PER_SECTOR * INDIRECT_CNT))
  {
    *offset_cnt = 2;
    offsets[0] = DIRECT_CNT;             /* Index in inode_disk.sectors[] for indirect root. */
    offsets[1] = (size_t) sector_idx;    /* Index inside the indirect block. */
    return;
  }

  /* Handle doubly indirect blocks. */
  // offset_cnt = 3, offsets[0] = DIRECT_CNT + INDIRECT_CNT, offsets[1], offsets[2] ...
  sector_idx -= (off_t) (PTRS_PER_SECTOR * INDIRECT_CNT);

  /* Doubly indirect blocks. */
  *offset_cnt = 3;
  offsets[0] = DIRECT_CNT + INDIRECT_CNT;              /* Index in inode_disk.sectors[] for dbl-indirect root. */
  offsets[1] = (size_t) (sector_idx / PTRS_PER_SECTOR);/* Which indirect block inside dbl-indirect. */
  offsets[2] = (size_t) (sector_idx % PTRS_PER_SECTOR);/* Entry inside that indirect block. */
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block and data_sector to the sector to write 
   (for inode_write_at method).
   Returns true if successful, false on failure.
   If ALLOCATE is false (usually for inode read), then missing blocks 
   will be successful with *DATA_BLOCK set to a null pointer.
   If ALLOCATE is true (for inode write), then missing blocks will be allocated. 
   This method may be called in parallel */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                void **data_block, block_sector_t *data_sector)
{
  // debug
// debug
// debug
// printf("=== get_data_block START ===\n");
  // debug
// debug
// debug
// printf("get_data_block: inode=%p, sector=%u, offset=%d, allocate=%s\n", inode, inode->sector, offset, allocate ? "true" : "false");
  
  ASSERT (inode != NULL);

  inode_assert_valid ("get_data_block", inode);
  inode_assert_sector_valid ("get_data_block", inode->sector);

  ASSERT (data_block != NULL);
  ASSERT (data_sector != NULL);

  /* Compute file block index. */
  off_t sector_idx = offset / BLOCK_SECTOR_SIZE;
  size_t offsets[3];
  size_t offset_cnt = 0;

  // debug
// debug
// debug
// printf("get_data_block: sector_idx = %d (offset %d / BLOCK_SECTOR_SIZE)\n", sector_idx, offset);
  
  calculate_indices (sector_idx, offsets, &offset_cnt);
  ASSERT (offset_cnt >= 1 && offset_cnt <= 3);
  
  // debug
// debug
// debug
// printf("get_data_block: offset_cnt = %zu, offsets = [", offset_cnt);
  // for (size_t i = 0; i < offset_cnt; i++)
    // debug
// debug
// debug
// printf("%zu%s", offsets[i], i < offset_cnt - 1 ? ", " : "");
  // debug
// debug
// debug
// printf("]\n");

  /* Read on-disk inode (single source of truth). */
  // debug
// debug
// debug
// printf("get_data_block: Reading disk_inode from sector %u...\n", inode->sector);
  struct inode_disk disk_inode;
  
  /* Acquire lock for reading/modifying inode */
  // lock_acquire (&inode->lock);
  block_read (fs_device, inode->sector, &disk_inode);
  
  // debug
// debug
// debug
// printf("get_data_block: disk_inode - length=%d, magic=0x%X\n", disk_inode.length, disk_inode.magic);

  bool inode_changed = false;
  void *block_buf = NULL;

  /* Convenience macro: if we see a missing block and !allocate,
     report "hole" (sparse) to caller. */
#define HANDLE_MISSING_IF_NOT_ALLOC(ptr)               \
  do {                                                 \
    if (*(ptr) == 0)                                   \
      {                                                \
        if (!allocate)                                 \
          {                                            \
            *data_block = NULL;                        \
            *data_sector = 0;                          \
            return true;                               \
          }                                            \
      }                                                \
  } while (0)

  /* DIRECT, INDIRECT, or DBL_INDIRECT traversal. */
  if (offset_cnt == 1)
    {
      // debug
// debug
// debug
// printf("get_data_block: Processing DIRECT block at index %zu\n", offsets[0]);
      
      /* Direct block. */
      block_sector_t *entry = &disk_inode.sectors[offsets[0]];
      HANDLE_MISSING_IF_NOT_ALLOC (entry);

      if (*entry == 0)
        {
          /* Need to allocate a new data sector. */
          // debug
// debug
// debug
// printf("get_data_block: Allocating new direct data sector...\n");
          if (!free_map_allocate (entry))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          // debug
// debug
// debug
// printf("get_data_block: Allocated direct sector %u\n", *entry);
          inode_changed = true;
          
          /* Zero-fill the new data sector and return it. */
          block_buf = calloc (1, BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - calloc failed for block_buf\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_write (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Wrote zeros to new sector %u\n", *entry);
          *data_block = block_buf;
          *data_sector = *entry;
        }
      else
        {
          /* Existing data sector. */
          // debug
// debug
// debug
// printf("get_data_block: Reading existing direct sector %u\n", *entry);
          block_buf = malloc (BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - malloc failed for block_buf\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_read (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Read existing sector %u\n", *entry);
          *data_block = block_buf;
          *data_sector = *entry;
        }
    }
  else if (offset_cnt == 2)
    {
      // debug
// debug
// debug
// printf("get_data_block: Processing INDIRECT block [%zu][%zu]\n",  offsets[0], offsets[1]);
      
      /* Single-indirect: sectors[DIRECT_CNT] → indirect block → data block. */
      block_sector_t *indirect_root = &disk_inode.sectors[offsets[0]];
      HANDLE_MISSING_IF_NOT_ALLOC (indirect_root);

      if (*indirect_root == 0)
        {
          // debug
// debug
// debug
// printf("get_data_block: Allocating indirect root block...\n");
          if (!free_map_allocate (indirect_root))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed for indirect root\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          // debug
// debug
// debug
// printf("get_data_block: Allocated indirect root at sector %u\n", *indirect_root);
          inode_changed = true;

          /* Zero the new indirect block. */
          block_sector_t zeros[PTRS_PER_SECTOR];
          memset (zeros, 0, sizeof zeros);
          block_write (fs_device, *indirect_root, zeros);
          // debug
// debug
// debug
// printf("get_data_block: Zeroed indirect root block\n");
        }
      else
        {
          // debug
// debug
// debug
// printf("get_data_block: Indirect root exists at sector %u\n", *indirect_root);
        }

      /* Read indirect block. */
      block_sector_t indirect[PTRS_PER_SECTOR];
      block_read (fs_device, *indirect_root, indirect);
      // debug
// debug
// debug
// printf("get_data_block: Read indirect block from sector %u\n", *indirect_root);

      block_sector_t *entry = &indirect[offsets[1]];
      HANDLE_MISSING_IF_NOT_ALLOC (entry);

      if (*entry == 0)
        {
          // debug
// debug
// debug
// printf("get_data_block: Allocating data sector in indirect block...\n");
          if (!free_map_allocate (entry))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed for data sector\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }

          // debug
// debug
// debug
// printf("get_data_block: Allocated data sector %u\n", *entry);
          
          /* Zero new data sector. */
          block_buf = calloc (1, BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - calloc failed\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_write (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Wrote zeros to new data sector %u\n", *entry);

          /* Write back updated indirect block. */
          block_write (fs_device, *indirect_root, indirect);
          // debug
// debug
// debug
// printf("get_data_block: Wrote back updated indirect block to sector %u\n",  *indirect_root);

          *data_block = block_buf;
          *data_sector = *entry;
        }
      else
        {
          // debug
// debug
// debug
// printf("get_data_block: Reading existing data sector %u\n", *entry);
          block_buf = malloc (BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - malloc failed\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_read (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Read existing data sector %u\n", *entry);
          *data_block = block_buf;
          *data_sector = *entry;
        }
    }
  else  /* offset_cnt == 3 */
    {
      // debug
// debug
// debug
// printf("get_data_block: Processing DOUBLY INDIRECT block [%zu][%zu][%zu]\n", offsets[0], offsets[1], offsets[2]);
      
      /* Double-indirect:
           sectors[DIRECT_CNT + INDIRECT_CNT] → dbl_indirect block
           dbl_indirect[idx1] → indirect block
           indirect[idx2] → data block
       */
      block_sector_t *dbl_root = &disk_inode.sectors[offsets[0]];
      HANDLE_MISSING_IF_NOT_ALLOC (dbl_root);

      if (*dbl_root == 0)
        {
          // debug
// debug
// debug
// printf("get_data_block: Allocating doubly indirect root...\n");
          if (!free_map_allocate (dbl_root))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed for dbl root\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          // debug
// debug
// debug
// printf("get_data_block: Allocated dbl indirect root at sector %u\n", *dbl_root);
          inode_changed = true;

          /* Zero new double-indirect block. */
          block_sector_t zeros[PTRS_PER_SECTOR];
          memset (zeros, 0, sizeof zeros);
          block_write (fs_device, *dbl_root, zeros);
          // debug
// debug
// debug
// printf("get_data_block: Zeroed dbl indirect root\n");
        }
      else
        {
          // debug
// debug
// debug
// printf("get_data_block: Dbl indirect root exists at sector %u\n", *dbl_root);
        }

      /* Read double-indirect block. */
      block_sector_t dbl[PTRS_PER_SECTOR];
      block_read (fs_device, *dbl_root, dbl);
      // debug
// debug
// debug
// printf("get_data_block: Read dbl indirect block from sector %u\n", *dbl_root);

      block_sector_t *indirect_root = &dbl[offsets[1]];
      HANDLE_MISSING_IF_NOT_ALLOC (indirect_root);

      if (*indirect_root == 0)
        {
          // debug
// debug
// debug
// printf("get_data_block: Allocating indirect block in dbl indirect...\n");
          if (!free_map_allocate (indirect_root))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed for indirect\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }

          // debug
// debug
// debug
// printf("get_data_block: Allocated indirect block at sector %u\n", *indirect_root);
          
          /* Zero new indirect block. */
          block_sector_t zeros[PTRS_PER_SECTOR];
          memset (zeros, 0, sizeof zeros);
          block_write (fs_device, *indirect_root, zeros);
          // debug
// debug
// debug
// printf("get_data_block: Zeroed indirect block\n");

          /* Write back updated double-indirect block. */
          block_write (fs_device, *dbl_root, dbl);
          // debug
// debug
// debug
// printf("get_data_block: Wrote back updated dbl indirect block to sector %u\n", *dbl_root);
        }
      else
        {
          // debug
// debug
// debug
// printf("get_data_block: Indirect block exists at sector %u\n", *indirect_root);
        }

      /* Read the indirect block pointed to by dbl[indirect index]. */
      block_sector_t indirect[PTRS_PER_SECTOR];
      block_read (fs_device, *indirect_root, indirect);
      // debug
// debug
// debug
// printf("get_data_block: Read indirect block from sector %u\n", *indirect_root);

      block_sector_t *entry = &indirect[offsets[2]];
      HANDLE_MISSING_IF_NOT_ALLOC (entry);

      if (*entry == 0)
        {
          // debug
// debug
// debug
// printf("get_data_block: Allocating data sector in indirect...\n");
          if (!free_map_allocate (entry))
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - free_map_allocate failed for data sector\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }

          // debug
// debug
// debug
// printf("get_data_block: Allocated data sector %u\n", *entry);
          
          /* Zero new data sector. */
          block_buf = calloc (1, BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - calloc failed\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_write (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Wrote zeros to new data sector %u\n", *entry);

          /* Write back updated indirect block. */
          block_write (fs_device, *indirect_root, indirect);
          // debug
// debug
// debug
// printf("get_data_block: Wrote back updated indirect block to sector %u\n", *indirect_root);

          *data_block = block_buf;
          *data_sector = *entry;
        }
      else
        {
          // debug
// debug
// debug
// printf("get_data_block: Reading existing data sector %u\n", *entry);
          block_buf = malloc (BLOCK_SECTOR_SIZE);
          if (block_buf == NULL)
            {
              // debug
// debug
// debug
// printf("get_data_block: ERROR - malloc failed\n");
              // lock_release (&inode->lock);
              // debug
// debug
// debug
// printf("=== get_data_block END (FAILURE) ===\n");
              return false;
            }
          
          block_read (fs_device, *entry, block_buf);
          // debug
// debug
// debug
// printf("get_data_block: Read existing data sector %u\n", *entry);
          *data_block = block_buf;
          *data_sector = *entry;
        }
    }

  /* If we modified the on-disk inode (e.g., new indirect/dbl-indirect roots),
     write it back. */
  if (inode_changed)
    {
      // debug
// debug
// debug
// printf("get_data_block: Writing back modified disk_inode to sector %u\n", inode->sector);
      block_write (fs_device, inode->sector, &disk_inode);
      // debug
// debug
// debug
// printf("get_data_block: disk_inode updated on disk\n");
    }

  // lock_release (&inode->lock);
  
  // debug
// debug
// debug
// printf("get_data_block: Success! data_sector=%u, data_block=%p\n", *data_sector, *data_block);
  // debug
// debug
// debug
// printf("=== get_data_block END (SUCCESS) ===\n");
  return true;

#undef HANDLE_MISSING_IF_NOT_ALLOC
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. 
   Modifications might be/might not be needed for this function template. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0)
    {
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      void *block = NULL;
      block_sector_t data_sector = (block_sector_t) -1;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      if (inode_left <= 0)
        break;

      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int chunk_size = size < inode_left ? size : inode_left;
      if (chunk_size > sector_left)
        chunk_size = sector_left;

      if (chunk_size <= 0)
        break;

      bool ok = get_data_block (inode, offset, false, &block, &data_sector);
      if (!ok)
        {
          // debug
        // debug
// debug
// printf("inode_read_at: get_data_block FAIL (inode=%p, offset=%d)\n", inode, (int) offset);
          break;
        }

      // debug
    // debug
// debug
// printf("inode_read_at: inode=%p (sector=%u), offset=%d, sector_ofs=%d, data_sector=%u, chunk=%d\n",inode, inode->sector, (int) offset, sector_ofs, data_sector, chunk_size);

      if (block == NULL)
        {
          /* Hole: treat as zero-filled. */
          memset (buffer + bytes_read, 0, chunk_size);
        }
      else
        {
          memcpy (buffer + bytes_read, (uint8_t *)block + sector_ofs, chunk_size);
          free (block);  /* Our get_data_block allocates a buffer. */
        }

      size        -= chunk_size;
      offset      += chunk_size;
      bytes_read  += chunk_size;
    }

  return bytes_read;
}


/* Extends INODE to be at least LENGTH bytes long. */
static void
extend_file (struct inode *inode, off_t length)
{
  // debug
// debug
// debug
// printf("=== extend_file START ===\n");
  // debug
// debug
// debug
// printf("extend_file: inode=%p, sector=%u, requested_length=%d\n", inode, inode->sector, length);

  inode_assert_valid ("extend_file", inode);
  inode_assert_sector_valid ("extend_file", inode->sector);
  
  ASSERT (inode != NULL);
  ASSERT (length >= 0);
  
  /* Read the current inode from disk (single source of truth) */
  // debug
// debug
// debug
// printf("extend_file: Reading disk_inode from sector %u...\n", inode->sector);
  struct inode_disk *disk_inode = malloc (sizeof *disk_inode);
  if (disk_inode == NULL)
    {
      // debug
// debug
// debug
// printf("extend_file: ERROR - Failed to allocate disk_inode buffer\n");
      // debug
// debug
// debug
// printf("=== extend_file END (FAILURE) ===\n");
      return;
    }
  
  // lock_acquire (&inode->lock);
  inode_assert_sector_valid ("extend_file/read", inode->sector);
  block_read (fs_device, inode->sector, disk_inode);
  
  // debug
// debug
// debug
// printf("extend_file: Current disk_inode state:\n");
  // debug
// debug
// debug
// printf("  - current length: %d\n", disk_inode->length);
  // debug
// debug
// debug
// printf("  - magic: 0x%X\n", disk_inode->magic);
  // debug
// debug
// debug
// printf("  - type: %d\n", disk_inode->type);
  // debug
// debug
// debug
// printf("  - direct_index: %u\n", disk_inode->direct_index);
  // debug
// debug
// debug
// printf("  - indirect_index: %u\n", disk_inode->indirect_index);
  // debug
// debug
// debug
// printf("  - dbl_indirect_index: %u\n", disk_inode->dbl_indirect_index);
  
  /* Check if extension is needed */
  if (length <= disk_inode->length)
    {
      // debug
// debug
// debug
// printf("extend_file: No extension needed (current=%d >= requested=%d)\n", disk_inode->length, length);
      // lock_release (&inode->lock);
      free (disk_inode);
      // debug
// debug
// debug
// printf("=== extend_file END (NO-OP) ===\n");
      return;
    }
  
  // debug
// debug
// debug
// printf("extend_file: Extension needed from %d to %d bytes\n", disk_inode->length, length);
  
  /* Check if we're exceeding maximum file size */
  if (length > INODE_SPAN)
    {
      // debug
// debug
// debug
// printf("extend_file: ERROR - Requested length %d exceeds INODE_SPAN %d\n", length, INODE_SPAN);
      // lock_release (&inode->lock);
      free (disk_inode);
      // debug
// debug
// debug
// printf("=== extend_file END (FAILURE - TOO LARGE) ===\n");
      return;
    }
  
  /* Update the length */
  off_t old_length = disk_inode->length;
  disk_inode->length = length;
  
  /* Calculate number of sectors needed for old and new lengths */
  size_t old_sectors = bytes_to_sectors (old_length);
  size_t new_sectors = bytes_to_sectors (length);
  
  // debug
// debug
// debug
// printf("extend_file: Old sectors: %zu, New sectors: %zu (delta: %zu)\n", old_sectors, new_sectors, new_sectors - old_sectors);
  
  /* Update the index fields based on new length */
  size_t sectors_needed = new_sectors;
  
  /* Update direct_index */
  if (sectors_needed > 0)
    {
      size_t direct_used = sectors_needed < DIRECT_CNT ? sectors_needed : DIRECT_CNT;
      disk_inode->direct_index = direct_used;
      sectors_needed -= direct_used;
      // debug
// debug
// debug
// printf("extend_file: direct_index set to %u (used %zu direct blocks)\n", disk_inode->direct_index, direct_used);
    }
  
  /* Update indirect_index */
  if (sectors_needed > 0)
    {
      size_t indirect_capacity = PTRS_PER_SECTOR * INDIRECT_CNT;
      size_t indirect_used = sectors_needed < indirect_capacity ? 
                             sectors_needed : indirect_capacity;
      disk_inode->indirect_index = indirect_used;
      sectors_needed -= indirect_used;
      // debug
// debug
// debug
// printf("extend_file: indirect_index set to %u (used %zu indirect blocks)\n", disk_inode->indirect_index, indirect_used);
    }
  else
    {
      disk_inode->indirect_index = 0;
    }
  
  /* Update dbl_indirect_index */
  if (sectors_needed > 0)
    {
      disk_inode->dbl_indirect_index = sectors_needed;
      // debug
// debug
// debug
// printf("extend_file: dbl_indirect_index set to %u\n", disk_inode->dbl_indirect_index);
    }
  else
    {
      disk_inode->dbl_indirect_index = 0;
    }
  
  // debug
// debug
// debug
// printf("extend_file: Updated indices - direct:%u, indirect:%u, dbl_indirect:%u\n", disk_inode->direct_index, disk_inode->indirect_index,  disk_inode->dbl_indirect_index);
  
  /* Write back the updated inode to disk */
  // debug
// debug
// debug
// printf("extend_file: Writing updated disk_inode back to sector %u...\n", inode->sector);
  block_write (fs_device, inode->sector, disk_inode);
  
  // debug
// debug
// debug
// printf("extend_file: Successfully extended file from %d to %d bytes\n", old_length, length);
  // debug
// debug
// debug
// printf("extend_file: Disk_inode written back with new length=%d\n", disk_inode->length);
  
  // lock_release (&inode->lock);
  free (disk_inode);
  
  // debug
// debug
// debug
// printf("=== extend_file END (SUCCESS) ===\n");
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. 
   Some modifications might be needed for this function template.*/
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  // debug
// debug
// debug
// printf("inode_write_at: inode=%p (sector=%u), size=%d, offset=%d\n",  inode, inode->sector, (int) size, (int) offset);

  /* Don't write if writes are denied. */
  lock_acquire (&inode->deny_write_lock);
  if (inode->deny_write_cnt)
    {
      lock_release (&inode->deny_write_lock);
      return 0;
    }
  inode->writer_cnt++;
  lock_release (&inode->deny_write_lock);

  while (size > 0)
    {
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      void *block = NULL;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = INODE_SPAN - offset;
      if (inode_left <= 0)
        break;

      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int chunk_size = size < inode_left ? size : inode_left;
      if (chunk_size > sector_left)
        chunk_size = sector_left;

      if (chunk_size <= 0)
        chunk_size = size < sector_left ? size : sector_left;

      block_sector_t data_sector = (block_sector_t) -1;
      bool ok = get_data_block (inode, offset, true, &block, &data_sector);
      if (!ok || block == NULL)
        {
          // debug
        // debug
// debug
// printf("inode_write_at: get_data_block FAILED (offset=%d)\n", (int) offset);
          break;
        }

      // debug
    // debug
// debug
// printf("inode_write_at: writing %d bytes at file offset=%d (sector_ofs=%d) to sector=%u\n", chunk_size, (int) offset, sector_ofs, data_sector);

      memcpy ((uint8_t *)block + sector_ofs, buffer + bytes_written, chunk_size);
      block_write (fs_device, data_sector, block);  /* <-- use data_sector, NOT target_sector */
      free (block);

      size         -= chunk_size;
      offset       += chunk_size;
      bytes_written += chunk_size;
    }

  /* Update on-disk length to new file size (offset is now end position). */
  extend_file (inode, offset);

  lock_acquire (&inode->deny_write_lock);
  if (--inode->writer_cnt == 0)
    cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
  lock_release (&inode->deny_write_lock);

  // debug
// debug
// debug
// printf("inode_write_at: DONE, bytes_written=%d\n", (int) bytes_written);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  // debug
// debug
// debug
// printf("=== inode_deny_write START ===\n");
  ASSERT (inode != NULL);

  // debug
// debug
// debug
// printf("inode_deny_write: inode=%p, sector=%u\n", (void *) inode, inode->sector);

  lock_acquire (&inode->deny_write_lock);

  // debug
// debug
// debug
// printf("inode_deny_write: current deny_write_cnt=%d, writer_cnt=%d\n", inode->deny_write_cnt, inode->writer_cnt);

  inode->deny_write_cnt++;
  // debug
// debug
// debug
// printf("inode_deny_write: incremented deny_write_cnt to %d\n", inode->deny_write_cnt);

  /* Wait for all active writers to finish. */
  while (inode->writer_cnt > 0)
    {
      // debug
// debug
// debug
// printf("inode_deny_write: waiting for writers to finish (writer_cnt=%d)\n", inode->writer_cnt);
      cond_wait (&inode->no_writers_cond, &inode->deny_write_lock);
      // debug
// debug
// debug
// printf("inode_deny_write: woke up, writer_cnt=%d\n", inode->writer_cnt);
    }

  // debug
// debug
// debug
// printf("inode_deny_write: no active writers left\n");

  lock_release (&inode->deny_write_lock);
  // debug
// debug
// debug
// printf("=== inode_deny_write END ===\n");
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  // debug
// debug
// debug
// printf("=== inode_allow_write START ===\n");
  ASSERT (inode != NULL);

  // debug
// debug
// debug
// printf("inode_allow_write: inode=%p, sector=%u\n", (void *) inode, inode->sector);

  lock_acquire (&inode->deny_write_lock);

  // debug
// debug
// debug
// printf("inode_allow_write: current deny_write_cnt=%d\n", inode->deny_write_cnt);
  ASSERT (inode->deny_write_cnt > 0);

  inode->deny_write_cnt--;
  // debug
// debug
// debug
// printf("inode_allow_write: decremented deny_write_cnt to %d\n", inode->deny_write_cnt);

  lock_release (&inode->deny_write_lock);
  // debug
// debug
// debug
// printf("=== inode_allow_write END ===\n");
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  // debug
// debug
// debug
// printf("inode_length: Called for inode at %p, sector %u\n",  inode, inode->sector);
  
  ASSERT (inode != NULL);
  inode_assert_valid ("inode_length", inode);
  
  /* Allocate temporary buffer for disk inode */
  struct inode_disk *disk_inode = malloc (sizeof *disk_inode);
  if (disk_inode == NULL)
    {
      // debug
// debug
// debug
// printf("inode_length: ERROR - Failed to allocate disk_inode buffer\n");
      PANIC ("inode_length: malloc failed");
    }
  
  /* Read inode data from disk (single source of truth) */
  // debug
// debug
// debug
// printf("inode_length: Reading inode_disk from sector %u...\n", inode->sector);
  inode_assert_sector_valid ("inode_length/read", inode->sector);
  block_read (fs_device, inode->sector, disk_inode);
  
  /* Verify magic number */
  if (disk_inode->magic != INODE_MAGIC)
    {
      // debug
// debug
// debug
// printf("inode_length: WARNING - Invalid magic number 0x%X (expected 0x%X)\n", disk_inode->magic, INODE_MAGIC);
    }
  
  /* Get the length */
  off_t length = disk_inode->length;
  
  // debug
// debug
// debug
// printf("inode_length: Length = %d bytes\n", length);
  // debug
// debug
// debug
// printf("inode_length: Additional info:\n");
  // debug
// debug
// debug
// printf("  - type: %d\n", disk_inode->type);
  // debug
// debug
// debug
// printf("  - direct_index: %u\n", disk_inode->direct_index);
  // debug
// debug
// debug
// printf("  - indirect_index: %u\n", disk_inode->indirect_index);
  // debug
// debug
// debug
// printf("  - dbl_indirect_index: %u\n", disk_inode->dbl_indirect_index);
  // debug
// debug
// debug
// printf("  - sectors needed: %zu\n", bytes_to_sectors(length));
  
  /* Free temporary buffer */
  free (disk_inode);
  // debug
// debug
// debug
// printf("inode_length: Returning %d\n", length);
  
  return length;
}

/* Returns the number of openers. */
int
inode_open_cnt (const struct inode *inode)
{
  int open_cnt;

  lock_acquire (&open_inodes_lock);
  open_cnt = inode->open_cnt;
  lock_release (&open_inodes_lock);

  return open_cnt;
}

/* Locks INODE. */
void
inode_lock (struct inode *inode)
{
  lock_acquire (&inode->lock);
}

/* Releases INODE's lock. */
void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->lock);
}

bool
inode_is_removed (const struct inode *inode)
{
  return inode->removed;
}