#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
 
/* Serializes file system operations. */
static struct lock fs_lock;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  typedef int syscall_func(int, int, int);
  struct syscall_tbl_entry 
  {
  	int argc;
  	syscall_func * func;
  };
  static struct syscall_tbl_entry syscall_tbl[] = 
  {
    [SYS_HALT     ] = {0, (syscall_func *) sys_halt },
    [SYS_EXIT     ] = {1, (syscall_func *) sys_exit },
    [SYS_EXEC     ] = {1, (syscall_func *) sys_exec },
    [SYS_WAIT     ] = {1, (syscall_func *) sys_wait },
    [SYS_CREATE   ] = {2, (syscall_func *) sys_create },
    [SYS_REMOVE   ] = {1, (syscall_func *) sys_remove },
    [SYS_OPEN     ] = {1, (syscall_func *) sys_open },
    [SYS_FILESIZE ] = {1, (syscall_func *) sys_filesize },
    [SYS_READ     ] = {3, (syscall_func *) sys_read },
    [SYS_WRITE    ] = {3, (syscall_func *) sys_write },
    [SYS_SEEK     ] = {2, (syscall_func *) sys_seek },
    [SYS_TELL     ] = {1, (syscall_func *) sys_tell },
    [SYS_CLOSE    ] = {1, (syscall_func *) sys_close }
  };
  
  int syscall_nr;
  int arg[3];
  
  copy_in(&syscall_nr, f->esp, sizeof(syscall_nr));
  copy_in(&arg, ((int*)f->esp) + 1, sizeof(arg));

  if(syscall_nr >= sizeof(syscall_tbl)) thread_exit();

  f->eax = syscall_tbl[syscall_nr].func(arg[0], arg[1], arg[2]);

}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  thread_current ()->wait_status->exit_code = exit_code;
  //printf ("%s: exit(%d)\n", thread_current ()->name, exit_code);
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
  /* Check pointer validity. */
  if (!verify_user (ufile)) 
  {
    thread_exit ();
  }

  int ret;
  char *kfile = copy_in_string (ufile);
  ret = process_execute (kfile);
  palloc_free_page (kfile);
  return ret;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
  /* Add code */
  return process_wait (child);
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{

  /* Check pointer validity. */
  if (!verify_user (ufile)) 
  {
    thread_exit ();
  }

  int ret;
  char *kfile = copy_in_string (ufile);
  ret = filesys_create (kfile, initial_size);
  palloc_free_page (kfile);
  return ret;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{
  /* Add code */
  int ret;
  char *kfile = copy_in_string (ufile);
  ret = filesys_remove (kfile);
  palloc_free_page (kfile);
  return ret;
}
 
/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };

 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  /* Check pointer validity. */
  if (!verify_user (ufile)) 
  {
    thread_exit ();
  }

  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
 
  fd = malloc (sizeof *fd);
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      fd->file = filesys_open (kfile);
      if (fd->file != NULL)
        {
          struct thread *cur = thread_current ();
          handle = fd->handle = cur->next_handle++;
          list_push_front (&cur->fds, &fd->elem);
        }
      else 
        free (fd);
      lock_release (&fs_lock);
    }
  palloc_free_page (kfile);
  return handle;
}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
/* Add code to lookup file descriptor in the current thread's fds */
  struct list_elem *thread_fd_elem = list_begin (&thread_current ()->fds);

  while(thread_fd_elem != NULL && thread_fd_elem != list_end (&thread_current ()->fds))
  {
  	if(list_entry (thread_fd_elem, struct file_descriptor, elem)->handle == handle)
  		return list_entry (thread_fd_elem, struct file_descriptor, elem);
  }
  thread_exit();
}

/* Removes a file descriptor with associated handle from the
   file descriptor list of the current thread. Returns 0 if
   fd removed, 1 otherwise. */
int
remove_fd (int handle)
{
  struct list_elem *thread_fd_elem = list_begin (&thread_current ()->fds);

  while(thread_fd_elem != NULL && thread_fd_elem != list_end (&thread_current ()->fds))
  {
        if(list_entry (thread_fd_elem, struct file_descriptor, elem)->handle == handle)
	{
                list_remove (thread_fd_elem);
		return 0;
	}
  }
  return 1;
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  int size;

  lock_acquire (&fs_lock);
  size = file_length (fd->file);
  lock_release (&fs_lock);

  return size;
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
  /* Add code */
  uint8_t *udst = udst_;
  off_t retval;
  int i, bytes_read;
  size_t read_amount;
  struct file_descriptor *fd = NULL;

  bytes_read =  0;
  read_amount = size;

  if (handle != STDIN_FILENO)
  	fd = lookup_fd (handle);

  lock_acquire (&fs_lock);

    /* Check that we can touch this user page. */
    if (!verify_user (udst)) 
    {
      lock_release (&fs_lock);
      thread_exit ();
    }

    if (handle == STDIN_FILENO)
    {
      for (i = 0; i < read_amount; i++) udst[i] = input_getc ();
      retval = read_amount;
	//printf("ifFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    }
    else
    {
      retval = file_read (fd->file, udst, read_amount);
	//printf("thenNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN %jd\n", (intmax_t)retval);
    }
////
  lock_release (&fs_lock);
  bytes_read += retval;
  return bytes_read;
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);


  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that we can touch this user page. */
      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          thread_exit ();
        }

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
  return bytes_written;
}
 
/* Seek system call. */
static int
sys_seek (int handle, unsigned position) 
{
  struct file_descriptor *fd = lookup_fd (handle);

  lock_acquire (&fs_lock);
  file_seek (fd->file, position);
  lock_release (&fs_lock);

  return 0;
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  int position;

  lock_acquire (&fs_lock);
  position = file_tell (fd->file);
  lock_release (&fs_lock);

  return position;
}
 
/* Close system call. */
static int
sys_close (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);

  lock_acquire (&fs_lock);
  file_close (fd->file);
  remove_fd (handle);
  lock_release (&fs_lock);

  return 0;
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
/* Add code */
  return;
}
