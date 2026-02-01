#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
}

/* Extracts a file name part from *SRCP into PART,
   and updates *SRCP so that the next call will return the next
   file name part.
   Returns 1 if successful, 0 at end of string, -1 for a too-long
   file name part. */
// NOTE: this is simple function to help you chop path string
// e.g. if 
//    char part[NAME_MAX];
//    const char* name = "/a/b/c";
// then:
//    1st get_next_part(part, name) // part: "a" name: "/b/c"
//    2nd get_next_part(part, name) // part: "b" name: "/c"
//    3rd get_next_part(part, name) // part: "c" name: ""
// you get the idea :)
static int
get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++;
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves relative or absolute file NAME.
   Returns true if successful, false on failure.
   Stores the directory corresponding to the name into *DIRP,
   and the file name part into BASE_NAME. */
static bool
resolve_name_to_entry (const char *name,
                       struct dir **dirp, char base_name[NAME_MAX + 1])
{
  // debug
// debug
// printf("resolve_name_to_entry: Resolving '%s'\n", name);
  
  ASSERT (name != NULL);
  ASSERT (dirp != NULL);
  ASSERT (base_name != NULL);
  
  struct dir *dir;
  char part[NAME_MAX + 1];
  const char *path = name;
  
  /* Start from root or current directory */
  if (name[0] == '/')
    {
      // debug
// debug
// printf("resolve_name_to_entry: Absolute path, starting from root\n");
      dir = dir_open_root ();
    }
  else
    {
      // debug
// debug
// printf("resolve_name_to_entry: Relative path (treating as root for now)\n");
      /* Use current working directory if set, otherwise root. */
      struct thread *t = thread_current ();
      if (t != NULL && t->cwd != NULL)
        dir = dir_reopen (t->cwd);
      else
        dir = dir_open_root ();
    }
  
  if (dir == NULL)
    {
      // debug
// debug
// printf("resolve_name_to_entry: ERROR - Failed to open starting directory\n");
      return false;
    }
  
  /* Parse the path component by component */
  int result;
  char next_part[NAME_MAX + 1];
  
  /* Peek at the next component to see if we have more */
  const char *temp_path = path;
  result = get_next_part (part, &path);
  
  if (result == -1)
    {
      // debug
// debug
// printf("resolve_name_to_entry: ERROR - Path component too long\n");
      dir_close (dir);
      return false;
    }
  
  if (result == 0)
    {
      /* Empty path - use current directory */
      // debug
// debug
// printf("resolve_name_to_entry: Empty path\n");
      dir_close (dir);
      return false;
    }
  
  /* Keep parsing until we reach the last component */
  while (true)
    {
      /* Peek ahead to see if there's another component */
      temp_path = path;
      int next_result = get_next_part (next_part, &temp_path);
      
      if (next_result == 0)
        {
          /* 'part' is the final component (the filename) */
          // debug
// debug
// printf("resolve_name_to_entry: Final component: '%s'\n", part);
          strlcpy (base_name, part, NAME_MAX + 1);
          *dirp = dir;
          // debug
// debug
// printf("resolve_name_to_entry: Success - dir=%p, base_name='%s'\n", dir, base_name);
          return true;
        }
      
      if (next_result == -1)
        {
          // debug
// debug
// printf("resolve_name_to_entry: ERROR - Path component too long\n");
          dir_close (dir);
          return false;
        }
      
      /* 'part' is a directory component, traverse it */
      // debug
// debug
// printf("resolve_name_to_entry: Traversing directory '%s'\n", part);
      
      struct inode *inode;
      if (!dir_lookup (dir, part, &inode))
        {
          // debug
// debug
// printf("resolve_name_to_entry: ERROR - Directory '%s' not found\n", part);
          dir_close (dir);
          return false;
        }
      
      /* Check if it's actually a directory */
      if (inode_get_type (inode) != DIR_INODE)
        {
          // debug
// debug
// printf("resolve_name_to_entry: ERROR - '%s' is not a directory\n", part);
          inode_close (inode);
          dir_close (dir);
          return false;
        }
      
      /* Move to the next directory */
      dir_close (dir);
      dir = dir_open (inode);
      
      if (dir == NULL)
        {
          // debug
// debug
// printf("resolve_name_to_entry: ERROR - Failed to open directory '%s'\n", part);
          inode_close (inode);
          return false;
        }
      
      /* Continue with the next component */
      strlcpy (part, next_part, NAME_MAX + 1);
      path = temp_path;
    }
}

/* Resolves relative or absolute file NAME to an inode.
   Returns an inode if successful, or a null pointer on failure.
   The caller is responsible for closing the returned inode. */
static struct inode *
resolve_name_to_inode (const char *name)
{
  // debug
// debug
// printf("resolve_name_to_inode: Resolving '%s'\n", name);
  
  struct dir *dir;
  char base_name[NAME_MAX + 1];
  
  if (!resolve_name_to_entry (name, &dir, base_name))
    {
      // debug
// debug
// printf("resolve_name_to_inode: Failed to resolve path\n");
      return NULL;
    }
  
  struct inode *inode;
  if (!dir_lookup (dir, base_name, &inode))
    {
      // debug
// debug
// printf("resolve_name_to_inode: '%s' not found in directory\n", base_name);
      dir_close (dir);
      return NULL;
    }
  
  dir_close (dir);
  // debug
// debug
// printf("resolve_name_to_inode: Found inode %p for '%s'\n", inode, name);
  return inode;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum inode_type type)
{
  // debug
  // debug
  // printf("=== filesys_create START ===\n");
  // debug
  // debug
  // printf("filesys_create: name='%s', initial_size=%d, type=%d (%s)\n", name, initial_size, type, type == FILE_INODE ? "FILE" : "DIR");
  
  ASSERT (name != NULL);
  ASSERT (initial_size >= 0);
  
  /* Validate name */
  if (strlen (name) == 0)
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - Empty name\n");
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  block_sector_t inode_sector = 0;
  bool success = false;
  
  /* Resolve the path to get the directory and filename */
  // debug
  // debug
  // printf("filesys_create: Resolving path '%s'...\n", name);
  struct dir *dir;
  char filename[NAME_MAX + 1];
  
  if (!resolve_name_to_entry (name, &dir, filename))
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - Failed to resolve path\n");
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  // debug
  // debug
  // printf("filesys_create: Resolved - filename='%s', dir=%p\n", filename, dir);

  /* NEW: do not create inside a removed parent directory. */
  struct inode *parent_inode = dir_get_inode (dir);
  if (parent_inode == NULL || inode_is_removed (parent_inode))
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - Parent directory inode is removed or NULL; cannot create '%s'\n", filename);
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE - PARENT REMOVED) ===\n");
      return false;
    }
  
  /* Don't allow creating "." or ".." entries */
  if (strcmp (filename, ".") == 0 || strcmp (filename, "..") == 0)
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - Cannot create '.' or '..' entries\n");
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  /* Check if file/directory already exists */
  struct inode *existing_inode = NULL;
  if (dir_lookup (dir, filename, &existing_inode))
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - File/directory '%s' already exists\n", filename);
      inode_close (existing_inode);
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE - ALREADY EXISTS) ===\n");
      return false;
    }
  
  // debug
  // debug
  // printf("filesys_create: File does not exist, proceeding with creation...\n");
  
  /* Allocate an inode sector */
  // debug
  // debug
  // printf("filesys_create: Allocating inode sector...\n");
  if (!free_map_allocate (&inode_sector))
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - Failed to allocate inode sector\n");
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  // debug
  // debug
  // printf("filesys_create: Allocated inode sector %u\n", inode_sector);
  
  /* Create the inode */
  // debug
  // debug
  // printf("filesys_create: Creating inode at sector %u...\n", inode_sector);
  struct inode *inode = inode_create (inode_sector, type);
  if (inode == NULL)
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - inode_create failed\n");
      free_map_release (inode_sector);
      // debug
      // debug
      // printf("filesys_create: Released inode sector %u back to free map\n", inode_sector);
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  // debug
  // debug
  // printf("filesys_create: Inode created successfully\n");
  
  /* If initial_size > 0, allocate space by writing zeros */
  if (initial_size > 0)
    {
      // debug
      // debug
      // printf("filesys_create: Allocating initial size of %d bytes...\n", (int) initial_size);

      static char zeros[BLOCK_SECTOR_SIZE];   /* BSS → initially zeroed. */
      off_t remaining = initial_size;
      off_t ofs       = 0;

      while (remaining > 0)
        {
          off_t chunk = remaining > BLOCK_SECTOR_SIZE
                        ? BLOCK_SECTOR_SIZE
                        : remaining;

          // debug
          // debug
          // printf("filesys_create: writing zero chunk: ofs=%d, chunk=%d\n", (int) ofs, (int) chunk);

          off_t written = inode_write_at (inode, zeros, chunk, ofs);

          // debug
          // debug
          // printf("filesys_create: inode_write_at returned %d (requested %d)\n", (int) written, (int) chunk);

          if (written != chunk)
            {
              // debug
              // debug
              // printf("filesys_create: ERROR - Failed to allocate full chunk; cleaning up inode and releasing sector %u\n",(unsigned) inode_sector);
              inode_remove (inode);
              inode_close (inode);
              free_map_release (inode_sector);
              // debug
              // printf("=== filesys_create END (FAILURE) ===\n");
              dir_close (dir);
              return false;
            }

          remaining -= written;
          ofs       += written;
        }

      // debug
      // debug
      // printf("filesys_create: zero-fill complete, final ofs=%d\n", (int) ofs);
    }
  
  /* Add the file/directory entry to the parent directory */
  // debug
  // debug
  // printf("filesys_create: Adding entry '%s' to directory (inode_sector=%u)...\n", filename, inode_sector);
  
  if (!dir_add (dir, filename, inode_sector))
    {
      // debug
      // debug
      // printf("filesys_create: ERROR - dir_add failed\n");
      inode_remove (inode);
      inode_close (inode);
      free_map_release (inode_sector);
      // debug
      // debug
      // printf("filesys_create: Cleaned up failed inode\n");
      dir_close (dir);
      // debug
      // debug
      // printf("=== filesys_create END (FAILURE) ===\n");
      return false;
    }
  
  // debug
  // debug
  // printf("filesys_create: Successfully added directory entry\n");
  
  /* If creating a directory, initialize it with "." and ".." entries */
  if (type == DIR_INODE)
    {
      // debug
      // debug
      // printf("filesys_create: Initializing directory with '.' and '..' entries...\n");

      /* Take a separate reference for the directory handle.
         dir_close(new_dir) will drop this reference, while the
         original 'inode' is closed at the end of filesys_create. */
      struct inode *dir_inode2 = inode_reopen (inode);
      if (dir_inode2 == NULL)
        {
          // debug
          // debug
          // printf("filesys_create: ERROR - inode_reopen failed for new directory\n");
          inode_remove (inode);
          inode_close (inode);
          dir_close (dir);
          // debug
          // debug
          // printf("=== filesys_create END (FAILURE) ===\n");
          return false;
        }

      struct dir *new_dir = dir_open (dir_inode2);
      if (new_dir == NULL)
        {
          // debug
          // debug
          // printf("filesys_create: ERROR - Failed to open new directory\n");
          /* dir_open() failed, so dir_inode2 is still our responsibility. */
          inode_remove (inode);
          inode_close (inode);
          inode_close (dir_inode2);
          dir_close (dir);
          // debug
          // debug
          // printf("=== filesys_create END (FAILURE) ===\n");
          return false;
        }
      
      /* Add "." (self) entry */
      if (!dir_add (new_dir, ".", inode_sector))
        {
          // debug
          // debug
          // printf("filesys_create: ERROR - Failed to add '.' entry\n");
          dir_close (new_dir);        /* closes dir_inode2 */
          inode_remove (inode);
          inode_close (inode);
          dir_close (dir);
          // debug
          // debug
          // printf("=== filesys_create END (FAILURE) ===\n");
          return false;
        }
      
      /* Add ".." (parent) entry */
      block_sector_t parent_sector2 = inode_get_inumber (dir_get_inode (dir));
      if (!dir_add (new_dir, "..", parent_sector2))
        {
          // debug
          // debug
          // printf("filesys_create: ERROR - Failed to add '..' entry\n");
          dir_close (new_dir);        /* closes dir_inode2 */
          inode_remove (inode);
          inode_close (inode);
          dir_close (dir);
          // debug
          // debug
          // printf("=== filesys_create END (FAILURE) ===\n");
          return false;
        }
      
      // debug
      // debug
      // printf("filesys_create: Directory initialized with '.' and '..' entries\n");
      dir_close (new_dir);            /* drops dir_inode2 reference */
    }
  
  /* Close the inode (we're done with it) */
  inode_close (inode);
  // debug
  // debug
  // printf("filesys_create: Closed inode\n");
  
  success = true;
  // debug
  // debug
  // printf("filesys_create: Success! Created '%s' with inode sector %u\n", filename, inode_sector);
  
  /* Cleanup */
  dir_close (dir);
  
  // debug
  // debug
  // printf("=== filesys_create END (SUCCESS) ===\n");
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
  // debug
// debug
// printf("=== filesys_open START ===\n");

  if (name == NULL)
    {
      // debug
// debug
// printf("filesys_open: ERROR - name is NULL\n");
      // debug
// debug
// printf("=== filesys_open END (FAIL - NULL NAME) ===\n");
      return NULL;
    }

  // debug
// debug
// printf("filesys_open: name=\"%s\"\n", name);

  if (strlen (name) == 0)
    {
      // debug
// debug
// printf("filesys_open: ERROR - empty name\n");
      // debug
// debug
// printf("=== filesys_open END (FAIL - EMPTY NAME) ===\n");
      return NULL;
    }

  /* Special case: root directory "/" */
  if (name[0] == '/' && name[1] == '\0')
    {
      // debug
// debug
// printf("filesys_open: Special case - root directory \"/\"\n");

      struct dir *root_dir = dir_open_root ();
      if (root_dir == NULL)
        {
          // debug
// debug
// printf("filesys_open: ERROR - dir_open_root() returned NULL\n");
          // debug
// debug
// printf("=== filesys_open END (FAIL - ROOT OPEN) ===\n");
          return NULL;
        }

      struct inode *root_inode = dir_get_inode (root_dir);
      if (root_inode == NULL)
        {
          // debug
// debug
// printf("filesys_open: ERROR - dir_get_inode(root_dir) returned NULL\n");
          dir_close (root_dir);
          // debug
// debug
// printf("=== filesys_open END (FAIL - ROOT INODE) ===\n");
          return NULL;
        }

      /* Take our own reference to the inode before closing the dir. */
      struct inode *inode = inode_reopen (root_inode);
      // debug
// debug
// printf("filesys_open: Opened root inode=%p, sector=%u, type=%d\n", (void *) inode, inode_get_inumber (inode), inode_get_type (inode));

      dir_close (root_dir);
      // debug
// debug
// printf("filesys_open: Closed temporary root_dir handle\n");
      // debug
// debug
// printf("=== filesys_open END (SUCCESS - ROOT) ===\n");
      return inode;
    }

  /* General case: resolve path to inode via helper. */
  // debug
// debug
// printf("filesys_open: Resolving path '%s' to inode...\n", name);
  struct inode *inode = resolve_name_to_inode (name);

  if (inode == NULL)
    {
      // debug
// debug
// printf("filesys_open: ERROR - resolve_name_to_inode failed for '%s'\n", name);
      // debug
// debug
// printf("=== filesys_open END (FAIL - NOT FOUND) ===\n");
      return NULL;
    }

  /* NEW: reject inodes that have been removed (e.g., cwd after rm). */
  if (inode_is_removed (inode))
    {
      // debug
// debug
// printf("filesys_open: inode for '%s' is marked removed (sector=%u) → failing open\n", name, inode_get_inumber (inode));
      inode_close (inode);
      // debug
// debug
// printf("=== filesys_open END (FAIL - REMOVED) ===\n");
      return NULL;
    }

  // debug
// debug
// printf("filesys_open: SUCCESS - inode=%p, sector=%u, type=%d\n", (void *) inode, inode_get_inumber (inode), inode_get_type (inode));

  // debug
// debug
// printf("=== filesys_open END (SUCCESS) ===\n");
  return inode;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  // debug
// debug
// printf("=== filesys_remove START ===\n");

  if (name == NULL)
    {
      // debug
// debug
// printf("filesys_remove: ERROR - name is NULL\n");
      // debug
// debug
// printf("=== filesys_remove END (FAIL - NULL NAME) ===\n");
      return false;
    }

  if (strlen (name) == 0)
    {
      // debug
// debug
// printf("filesys_remove: ERROR - empty name\n");
      // debug
// debug
// printf("=== filesys_remove END (FAIL - EMPTY NAME) ===\n");
      return false;
    }

  /* Do not allow removing the root directory via "/" */
  if (name[0] == '/' && name[1] == '\0')
    {
      // debug
// debug
// printf("filesys_remove: ERROR - cannot remove root directory\n");
      // debug
// debug
// printf("=== filesys_remove END (FAIL - ROOT) ===\n");
      return false;
    }

  struct dir *dir;
  char filename[NAME_MAX + 1];

  if (!resolve_name_to_entry (name, &dir, filename))
    {
      // debug
// debug
// printf("filesys_remove: ERROR - resolve_name_to_entry failed for '%s'\n", name);
      // debug
// debug
// printf("=== filesys_remove END (FAIL - RESOLVE) ===\n");
      return false;
    }

  // debug
// debug
// printf("filesys_remove: Resolved name='%s', filename='%s', dir=%p\n", name, filename, dir);

  /* Don't allow removing "." or "..". */
  if (strcmp (filename, ".") == 0 || strcmp (filename, "..") == 0)
    {
      // debug
// debug
// printf("filesys_remove: ERROR - cannot remove '.' or '..'\n");
      dir_close (dir);
      // debug
// debug
// printf("=== filesys_remove END (FAIL - DOT) ===\n");
      return false;
    }

  struct inode *inode = NULL;
  if (!dir_lookup (dir, filename, &inode))
    {
      // debug
// debug
// printf("filesys_remove: ERROR - entry '%s' not found\n", filename);
      dir_close (dir);
      // debug
// debug
// printf("=== filesys_remove END (FAIL - NOT FOUND) ===\n");
      return false;
    }

  enum inode_type type = inode_get_type (inode);

  if (type == DIR_INODE)
    {
      // debug
// debug
// printf("filesys_remove: Target is a directory\n");

      /* Disallow removing the root directory. */
      if (inode_get_inumber (inode) == ROOT_DIR_SECTOR)
        {
          // debug
// debug
// printf("filesys_remove: ERROR - target is root directory\n");
          inode_close (inode);
          dir_close (dir);
          // debug
// debug
// printf("=== filesys_remove END (FAIL - ROOT DIR) ===\n");
          return false;
        }

      /* Open the directory to inspect its contents.
         dir_open() takes ownership of INODE, so do not close it separately. */
      struct dir *target_dir = dir_open (inode);
      if (target_dir == NULL)
        {
          // debug
// debug
// printf("filesys_remove: ERROR - dir_open on target directory failed\n");
          inode_close (inode);
          dir_close (dir);
          // debug
// debug
// printf("=== filesys_remove END (FAIL - OPEN DIR) ===\n");
          return false;
        }

      /* Check if directory is empty (aside from '.' and '..').
         dir_readdir is expected to skip '.' and '..', so any entry
         we see here means the directory is not empty. */
      char entry_name[NAME_MAX + 1];
      bool empty = true;
      if (dir_readdir (target_dir, entry_name))
        {
          empty = false;
        }

      dir_close (target_dir);

      if (!empty)
        {
          // debug
// debug
// printf("filesys_remove: ERROR - directory '%s' is not empty\n", filename);
          dir_close (dir);
          // debug
// debug
// printf("=== filesys_remove END (FAIL - NOT EMPTY) ===\n");
          return false;
        }

      /* Now actually remove the entry from the parent directory. */
      bool success = dir_remove (dir, filename);
      dir_close (dir);

      // debug
// debug
// printf("filesys_remove: dir_remove('%s') returned %d\n", filename, success);
      // debug
// debug
// printf("=== filesys_remove END (%s) ===\n", success ? "SUCCESS" : "FAIL");
      return success;
    }
  else
    {
      // debug
// debug
// printf("filesys_remove: Target is a regular file\n");

      /* Close our inode reference; dir_remove will fetch and close its own. */
      inode_close (inode);

      bool success = dir_remove (dir, filename);
      dir_close (dir);

      // debug
// debug
// printf("filesys_remove: dir_remove('%s') returned %d\n", filename, success);
      // debug
// debug
// printf("=== filesys_remove END (%s) ===\n", success ? "SUCCESS" : "FAIL");
      return success;
    }
}

/* Change current directory to NAME.
   Return true if successful, false on failure. */
bool
filesys_chdir (const char *name)
{
  // debug
// debug
// printf("=== filesys_chdir START ===\n");

  if (name == NULL)
    {
      // debug
// debug
// printf("filesys_chdir: ERROR - name is NULL\n");
      // debug
// debug
// printf("=== filesys_chdir END (FAIL - NULL NAME) ===\n");
      return false;
    }

  if (strlen (name) == 0)
    {
      // debug
// debug
// printf("filesys_chdir: ERROR - empty name\n");
      // debug
// debug
// printf("=== filesys_chdir END (FAIL - EMPTY NAME) ===\n");
      return false;
    }

  struct thread *t = thread_current ();

  /* Special case: root directory "/" */
  if (name[0] == '/' && name[1] == '\0')
    {
      // debug
// debug
// printf("filesys_chdir: Special case - root directory \"/\"\n");

      struct dir *new_dir = dir_open_root ();
      if (new_dir == NULL)
        {
          // debug
// debug
// printf("filesys_chdir: ERROR - dir_open_root() failed\n");
          // debug
// debug
// printf("=== filesys_chdir END (FAIL - ROOT OPEN) ===\n");
          return false;
        }

      if (t->cwd != NULL)
        dir_close (t->cwd);
      t->cwd = new_dir;

      // debug
// debug
// printf("filesys_chdir: Changed cwd to root\n");
      // debug
// debug
// printf("=== filesys_chdir END (SUCCESS) ===\n");
      return true;
    }

  /* General case: resolve path to inode. */
  // debug
// debug
// printf("filesys_chdir: Resolving path '%s'...\n", name);

  struct inode *inode = resolve_name_to_inode (name);
  if (inode == NULL)
    {
      // debug
// debug
// printf("filesys_chdir: ERROR - resolve_name_to_inode failed for '%s'\n", name);
      // debug
// debug
// printf("=== filesys_chdir END (FAIL - RESOLVE) ===\n");
      return false;
    }

  if (inode_get_type (inode) != DIR_INODE)
    {
      // debug
// debug
// printf("filesys_chdir: ERROR - target is not a directory\n");
      inode_close (inode);
      // debug
// debug
// printf("=== filesys_chdir END (FAIL - NOT DIR) ===\n");
      return false;
    }

  struct dir *new_dir = dir_open (inode);
  if (new_dir == NULL)
    {
      // debug
// debug
// printf("filesys_chdir: ERROR - dir_open on target directory failed\n");
      inode_close (inode);
      // debug
// debug
// printf("=== filesys_chdir END (FAIL - OPEN DIR) ===\n");
      return false;
    }

  if (t->cwd != NULL)
    dir_close (t->cwd);
  t->cwd = new_dir;

  // debug
// debug
// printf("filesys_chdir: Successfully changed cwd to '%s'\n", name);
  // debug
// debug
// printf("=== filesys_chdir END (SUCCESS) ===\n");
  return true;
}


/* Formats the file system. */
static void
do_format (void)
{
  struct inode *inode;
// debug
// printf ("Formatting file system...");

  /* Set up free map. */
  free_map_create ();

  /* Set up root directory. */
  inode = dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);

  if (inode == NULL)
    PANIC ("root directory creation failed");
  inode_close (inode);

  free_map_close ();

// debug
// printf ("done.\n");
}
