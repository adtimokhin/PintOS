#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/free-map.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory in the given SECTOR.
   The directory's parent is in PARENT_SECTOR.
   Returns inode of created directory if successful,
   null pointer on failure.
   On failure, SECTOR is released in the free map. */
struct inode *
dir_create (block_sector_t sector, block_sector_t parent_sector)
{
  // debug
// debug
// printf("=== dir_create START ===\n");
  // debug
// debug
// printf("dir_create: sector=%u, parent_sector=%u\n", sector, parent_sector);

  /* 1. Create the inode for the directory. */
  struct inode *inode = inode_create (sector, DIR_INODE);
  if (inode == NULL)
    {
      // debug
// debug
// printf("dir_create: inode_create failed\n");
      // debug
// debug
// printf("=== dir_create END (FAILURE) ===\n");
      return NULL;
    }
  // debug
// debug
// printf("dir_create: Directory inode created successfully (inode=%p)\n", (void *) inode);

  /* 2. Take a second reference specifically for the dir handle. */
  // debug
// debug
// printf("dir_create: Reopening inode for dir handle...\n");
  struct inode *inode_for_dir = inode_reopen (inode);
  if (inode_for_dir == NULL)
    {
      // debug
// debug
// printf("dir_create: inode_reopen failed\n");
      inode_remove (inode);
      inode_close (inode);
      // debug
// debug
// printf("=== dir_create END (FAILURE - reopen) ===\n");
      return NULL;
    }

  // debug
// debug
// printf("dir_create: inode_reopen ok: inode_for_dir=%p\n", (void *) inode_for_dir);

  /* 3. Open a directory object on the reopened inode. */
  // debug
// debug
// printf("dir_create: Opening directory to add '.' and '..' entries...\n");
  struct dir *dir = dir_open (inode_for_dir);
  if (dir == NULL)
    {
      // debug
// debug
// printf("dir_create: dir_open failed\n");
      inode_remove (inode);
      inode_close (inode_for_dir);  /* drop reopen ref */
      inode_close (inode);          /* drop original ref */
      // debug
// debug
// printf("=== dir_create END (FAILURE - dir_open) ===\n");
      return NULL;
    }

  /* 4. Add '.' and '..' entries. */
  if (!dir_add (dir, ".", sector))
    {
      // debug
// debug
// printf("dir_create: ERROR while adding '.' entry\n");
      dir_close (dir);        /* drops inode_for_dir ref */
      inode_remove (inode);
      inode_close (inode);    /* drop original ref */
      // debug
// debug
// printf("=== dir_create END (FAILURE - '.') ===\n");
      return NULL;
    }

  if (!dir_add (dir, "..", parent_sector))
    {
      // debug
// debug
// printf("dir_create: ERROR while adding '..' entry\n");
      dir_close (dir);        /* drops inode_for_dir ref */
      inode_remove (inode);
      inode_close (inode);    /* drop original ref */
      // debug
// debug
// printf("=== dir_create END (FAILURE - '..') ===\n");
      return NULL;
    }

  // debug
// debug
// printf("dir_create: Directory initialized successfully\n");

  /* 5. Close temporary dir handle (drops inode_for_dir). 
        Original inode is still open (open_cnt == 1). */
  dir_close (dir);

  // debug
// debug
// printf("dir_create: Final directory structure:\n");
  // debug
// debug
// printf("  - sector: %u\n", sector);
  // debug
// debug
// printf("  - parent: %u\n", parent_sector);
  // debug
// debug
// printf("=== dir_create END (SUCCESS) ===\n");

  /* Return the original inode. Caller (do_format) will close it once. */
  return inode;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  // debug
// debug
// printf("=== dir_open START ===\n");
  // debug
// debug
// printf("dir_open: inode=%p\n", inode);

  if (inode == NULL)
    {
      // debug
// debug
// printf("dir_open: inode is NULL → returning NULL\n");
      // debug
// debug
// printf("=== dir_open END (FAIL - NULL INODE) ===\n");
      return NULL;
    }

  /* Figure out the inode type once, so we can both log and branch on it. */
  enum inode_type type = inode_get_type (inode);
  const char *type_str = "UNKNOWN";
  if (type == DIR_INODE)
    type_str = "DIR";
  else if (type == FILE_INODE)
    type_str = "FILE";

  // debug
// debug
// printf("dir_open: inode=%p, type=%d (%s)\n",inode, (int) type, type_str);

  struct dir *dir = calloc (1, sizeof *dir);
  // debug
// debug
// printf("dir_open: allocated dir=%p (size=%zu)\n", dir, sizeof *dir);

  if (dir != NULL && type == DIR_INODE)
    {
      dir->inode = inode;
      dir->pos = 0;
      // debug
// debug
// printf("dir_open: SUCCESS - dir=%p now owns inode=%p\n", dir, inode);
      // debug
// debug
// printf("=== dir_open END (SUCCESS) ===\n");
      return dir;
    }
  else
    {
      if (dir == NULL)
        // debug
// debug
// printf("dir_open: calloc failed (dir is NULL)\n");
      if (type != DIR_INODE)
        // debug
// debug
// printf("dir_open: inode type is not DIR (type=%d/%s) → closing inode\n", (int) type, type_str);

      inode_close (inode);
      free (dir);

      // debug
// debug
// printf("dir_open: FAILURE - cleaned up inode and dir\n");
      // debug
// debug
// printf("=== dir_open END (FAIL) ===\n");
      return NULL;
    }
}


/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  // debug
// debug
// printf("dir_open_root: Opening the root directory");
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns the file's entry;
   otherwise, returns a null pointer. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;
  bool ok;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* NEW: if this directory has been removed, deny all lookups. */
  if (inode_is_removed (dir->inode))
    {
      // optional debug:
      // printf("dir_lookup: directory inode %u is removed, denying lookup for '%s'\n",
      //        inode_get_inumber (dir->inode), name);
      *inode = NULL;
      return false;
    }

  inode_lock (dir->inode);
  ok = lookup (dir, name, &e, NULL);
  inode_unlock (dir->inode);

  *inode = ok ? inode_open (e.inode_sector) : NULL;
  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strchr (name, '/') || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  inode_lock (dir->inode);
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  inode_unlock (dir->inode);
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (!strcmp (name, ".") || !strcmp (name, ".."))
    return false;

  /* Find directory entry. */
  inode_lock (dir->inode);
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* NOTE: Verify that it is not an in-use or non-empty directory. */
  // ....
  // ....
  // ....

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_unlock (dir->inode);
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  inode_lock (dir->inode);
  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;

        if (e.in_use && strcmp(e.name, ".")  != 0 && strcmp(e.name, "..") != 0)
        {
          inode_unlock (dir->inode);
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  inode_unlock (dir->inode);
  return false;
}
