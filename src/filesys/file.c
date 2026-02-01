#include "filesys/file.h"
#include <debug.h>
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* An open file. */
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

/* Creates a file in the given SECTOR,
   initially LENGTH bytes long. 
   Returns inode for the file on success, null pointer on failure.
   On failure, SECTOR is released in the free map. */
struct inode *
file_create (block_sector_t sector, off_t length) 
{
// debug
// printf("=== file_create START ===\n");
// debug
// printf("file_create: sector=%u, initial length=%d\n", (unsigned) sector, (int) length);

  /* Create the inode on disk + in memory. */
  struct inode *inode = inode_create (sector, FILE_INODE);
  if (inode == NULL)
    {
    // debug
// printf("file_create: ERROR - inode_create failed for sector %u\n", (unsigned) sector);
    // debug
// printf("=== file_create END (FAILURE) ===\n");
      return NULL;
    }

// debug
// printf("file_create: inode created successfully at sector %u (inode=%p)\n", (unsigned) sector, (void *) inode);

  if (length > 0)
    {
      /* Allocate space by writing zeros to the file, in 1-block chunks. */
      static char zeros[BLOCK_SECTOR_SIZE]; /* BSS → already zeroed. */
      off_t remaining = length;
      off_t ofs = 0;

    // debug
// printf("file_create: zero-filling file, total=%d bytes\n", (int) length);

      while (remaining > 0)
        {
          off_t chunk = remaining > BLOCK_SECTOR_SIZE
                        ? BLOCK_SECTOR_SIZE
                        : remaining;

        // debug
// printf("file_create: writing zero chunk: ofs=%d, chunk=%d\n", (int) ofs, (int) chunk);

          off_t written = inode_write_at (inode, zeros, chunk, ofs);

        // debug
// printf("file_create: inode_write_at returned %d (requested %d) MAYBE INCORRECT DEBUG STATEMENT!\n", written, zeros);
          if (written != chunk)
            {
            // debug
// printf("file_create: ERROR - Failed to allocate full chunk\n");
            // debug
// printf("file_create: Removing inode and releasing sector %u\n", (unsigned) sector);
              inode_remove (inode);
              inode_close (inode);
            // debug
// printf("=== file_create END (FAILURE) ===\n");
              return NULL;
            }

          remaining -= written;
          ofs       += written;
        }

    // debug
// printf("file_create: zero-fill complete, final ofs=%d\n", (int) ofs);
    }
  else
    {
    // debug
// printf("file_create: length == 0, skipping zero-fill\n");
    }

// debug
// printf("file_create: File successfully created with length %d\n", (int) length);
// debug
// printf("=== file_create END (SUCCESS) ===\n");
  return inode;
}


/* Opens a file for the given INODE, of which it takes ownership,
   and returns the new file.  Returns a null pointer if an
   allocation fails or if INODE is null. */
struct file *
file_open (struct inode *inode) 
{
  struct file *file = calloc (1, sizeof *file);
  if (inode != NULL && file != NULL && inode_get_type (inode) == FILE_INODE)
    {
      file->inode = inode;
      file->pos = 0;
      file->deny_write = false;
      return file;
    }
  else
    {
      inode_close (inode);
      free (file);
      return NULL; 
    }
}

/* Opens and returns a new file for the same inode as FILE.
   Returns a null pointer if unsuccessful. */
struct file *
file_reopen (struct file *file) 
{
  return file_open (inode_reopen (file->inode));
}

/* Closes FILE. */
void
file_close (struct file *file) 
{
  if (file != NULL)
    {
      file_allow_write (file);
      inode_close (file->inode);
      free (file); 
    }
}

/* Returns the inode encapsulated by FILE. */
struct inode *
file_get_inode (struct file *file) 
{
  return file->inode;
}

/* Reads SIZE bytes from FILE into BUFFER,
   starting at the file's current position.
   Returns the number of bytes actually read,
   which may be less than SIZE if end of file is reached.
   Advances FILE's position by the number of bytes read. */
off_t
file_read (struct file *file, void *buffer, off_t size) 
{
  off_t bytes_read = inode_read_at (file->inode, buffer, size, file->pos);
  file->pos += bytes_read;
  return bytes_read;
}

/* Reads SIZE bytes from FILE into BUFFER,
   starting at offset FILE_OFS in the file.
   Returns the number of bytes actually read,
   which may be less than SIZE if end of file is reached.
   The file's current position is unaffected. */
off_t
file_read_at (struct file *file, void *buffer, off_t size, off_t file_ofs) 
{
  return inode_read_at (file->inode, buffer, size, file_ofs);
}

/* Writes SIZE bytes from BUFFER into FILE,
   starting at the file's current position.
   Returns the number of bytes actually written,
   which may be less than SIZE if an error occurs.
   Advances FILE's position by the number of bytes written. */
off_t
file_write (struct file *file, const void *buffer, off_t size) 
{
// debug
// printf("=== file_write START ===\n");

  if (file == NULL)
    {
    // debug
// printf("file_write: ERROR - file is NULL (buffer=%p, size=%d)\n", buffer, (int) size);
    // debug
// printf("=== file_write END (FAIL - NULL FILE) ===\n");
      return 0;
    }

  if (buffer == NULL)
    {
    // debug
// printf("file_write: ERROR - buffer is NULL (file=%p, size=%d)\n", file, (int) size);
    // debug
// printf("=== file_write END (FAIL - NULL BUFFER) ===\n");
      return 0;
    }

  if (size <= 0)
    {
    // debug
// printf("file_write: size <= 0 (%d), nothing to do (file=%p, buffer=%p)\n", (int) size, file, buffer);
    // debug
// printf("=== file_write END (NO-OP) ===\n");
      return 0;
    }

  block_sector_t sector = (block_sector_t) -1;
  if (file->inode != NULL)
    sector = inode_get_inumber (file->inode); 

// debug
// printf("file_write: file=%p inode=%p sector=%u buffer=%p size=%d pos=%d\n",
        //  (void *) file,
        //  (void *) file->inode,
        //  (unsigned) sector,
        //  buffer,
        //  (int) size,
        //  (int) file->pos);

  /* Core write */
  off_t bytes_written = inode_write_at (file->inode, buffer, size, file->pos);

// debug
// printf("file_write: inode_write_at returned %d (requested %d)\n", (int) bytes_written, (int) size);

  if (bytes_written > 0)
    {
      file->pos += bytes_written;
    // debug
// printf("file_write: new file->pos=%d\n", (int) file->pos);
    }
  else
    {
    // debug
// printf("file_write: no bytes written, file->pos unchanged=%d\n", (int) file->pos);
    }

  // debug
  // printf("=== file_write END ===\n");
  return bytes_written;
}


/* Writes SIZE bytes from BUFFER into FILE,
   starting at offset FILE_OFS in the file.
   Returns the number of bytes actually written,
   which may be less than SIZE if end of file is reached.
   (Normally we'd grow the file in that case, but file growth is
   not yet implemented.)
   The file's current position is unaffected. */
off_t
file_write_at (struct file *file, const void *buffer, off_t size,
               off_t file_ofs) 
{
  return inode_write_at (file->inode, buffer, size, file_ofs);
}

/* Prevents write operations on FILE's underlying inode
   until file_allow_write() is called or FILE is closed. */
void
file_deny_write (struct file *file) 
{
  ASSERT (file != NULL);
  if (!file->deny_write) 
    {
      file->deny_write = true;
      // debug
// debug
// printf("file_deny_write: calling inode_deny_write(%p)\n", (void *) file->inode);
      inode_deny_write (file->inode);
    }
}

/* Re-enables write operations on FILE's underlying inode.
   (Writes might still be denied by some other file that has the
   same inode open.) */
void
file_allow_write (struct file *file) 
{
  ASSERT (file != NULL);
  if (file->deny_write) 
    {
      file->deny_write = false;
      inode_allow_write (file->inode);
    }
}

/* Returns the size of FILE in bytes. */
off_t
file_length (struct file *file) 
{
  ASSERT (file != NULL);
  return inode_length (file->inode);
}

/* Sets the current position in FILE to NEW_POS bytes from the
   start of the file. */
void
file_seek (struct file *file, off_t new_pos)
{
  ASSERT (file != NULL);
  ASSERT (new_pos >= 0);
  file->pos = new_pos;
}

/* Returns the current position in FILE as a byte offset from the
   start of the file. */
off_t
file_tell (struct file *file) 
{
  ASSERT (file != NULL);
  return file->pos;
}
