#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>  /* printk() */
#include <linux/errno.h>   /* error codes */
#include <linux/types.h>   /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/file.h>

#include "spinlock.h"
#include "osprd.h"

/* The size of an OSPRD sector. */
#define SECTOR_SIZE	512

/* This flag is added to an OSPRD file's f_flags to indicate that the file
 * is locked. */
#define F_OSPRD_LOCKED	0x80000

/* eprintk() prints messages to the console.
 * (If working on a real Linux machine, change KERN_NOTICE to KERN_ALERT or
 * KERN_EMERG so that you are sure to see the messages.  By default, the
 * kernel does not print all messages to the console.  Levels like KERN_ALERT
 * and KERN_EMERG will make sure that you will see messages.) */
#define eprintk(format, ...) printk(KERN_NOTICE format, ## __VA_ARGS__)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CS 111 RAM Disk");
// EXERCISE: Pass your names into the kernel as the module's authors.
MODULE_AUTHOR("Simon Zou & Vivian Zhang");

#define OSPRD_MAJOR	222

/* This module parameter controls how big the disk will be.
 * You can specify module parameters when you load the module,
 * as an argument to insmod: "insmod osprd.ko nsectors=4096" */
static int nsectors = 32;
module_param(nsectors, int, 0);
struct node
{
	pid_t pid;
	struct node* before;
	struct node* next;
};

struct pid_list
{
	struct node* head;
	int size;
};

struct ticket_node
{
	unsigned ticket;
	struct ticket_node* before;
	struct ticket_node* next;
};

struct ticket_list
{
	struct ticket_node* head;
	int size;
};

typedef struct osprd_info {
	uint8_t *data;                  // The data array. Its size is
	                                // (nsectors * SECTOR_SIZE) bytes.

	osp_spinlock_t mutex;           // Mutex for synchronizing access to
					// this block device

	unsigned ticket_head;		// Currently running ticket for
					// the device lock

	unsigned ticket_tail;		// Next available ticket for
					// the device lock

	wait_queue_head_t blockq;       // Wait queue for tasks blocked on
					// the device lock

	/* HINT: You may want to add additional fields to help
	         in detecting deadlock. */
	struct pid_list* read_list;
	struct pid_list* write_list;

	struct ticket_list* exited_tickets;


	// The following elements are used internally; you don't need
	// to understand them.
	struct request_queue *queue;    // The device request queue.
	spinlock_t qlock;		// Used internally for mutual
	                                //   exclusion in the 'queue'.
	struct gendisk *gd;             // The generic disk.
} osprd_info_t;



void add_to_pid_list(struct pid_list* l, pid_t pid)
{
	struct node* new;

	if(l == NULL)
	{
		l = kzalloc(sizeof(struct pid_list), GFP_ATOMIC);
		l->head = NULL;
		l->size = 0;
	}

	new = kzalloc(sizeof(struct node),GFP_ATOMIC);
	new->pid = pid;

	if (l->head == NULL)
	{
		l->head = new;
		new->before = NULL;
		new->next = NULL;
	}
	else 
	{
		new->next = l->head;
		l->head->before = new;
		l->head = new;
	}

	l->size ++;
}

void remove_from_pid_list(struct pid_list* l, pid_t to_remove)
{

	struct node* curr;
	if (l == NULL)
		return;

	if(l->head == NULL)
		return;

	curr = l->head;

	while(curr != NULL)
	{
		if(curr->pid == to_remove)
		{
			struct node* temp = curr;

			if(curr->before != NULL)
				curr->before->next = curr->next;
			else 
				l->head = curr->next;

			if(curr->next != NULL)
				curr->next->before = curr->before;

			kfree(temp);
			l->size --;
		}
		else 
			curr = curr->next;
	}

	if(l->size == 0)
	{
		kfree(l);
		l = NULL;
	}
} 

int pid_in_list(struct pid_list* l, pid_t to_find)
{

	struct node* curr;

	if(l == NULL)
		return 0;
	
	curr = l->head;

	while(curr != NULL)
	{
		if(curr->pid == to_find)
			return 1;
		curr = curr->next;
	}
	return 0;
}

void add_to_ticket_list(struct ticket_list* l, unsigned t)
{

	struct ticket_node* new2;

	if(l == NULL)
	{
		l= kzalloc(sizeof(struct ticket_list), GFP_ATOMIC);
		l->head = NULL;
		l->size = 0;
	}


	new2 = kzalloc(sizeof(struct ticket_node),GFP_ATOMIC);
	new2->ticket = t;
	new2->before = NULL;

	if(l->head == NULL)
	{
		l->head = new2;
		new2->next = NULL;
		l->size = 0;
	}
	else
	{
		l->head->before = new2;
		new2->next = l->head;
		l->head = new2;
	}

	l->size ++;

}

void remove_from_ticket_list(struct ticket_list* l, unsigned t)
{
	struct ticket_node* curr; 
	
	if(l == NULL)
		return;

	curr = l->head;
	
	if(curr == NULL)
		return;

	while(curr != NULL)
	{
		if(curr->ticket == t)
		{
			struct ticket_node* temp = curr;

			if(curr->before != NULL)
				curr->before->next = curr->next;
			else 
				l->head = curr->next;

			if(curr->next != NULL)
				curr->next->before = curr->before;

			kfree(temp);
			l->size --;
		}
		else 
			curr = curr->next;
	}

	if(l->size == 0)
	{
		kfree(l);
		l = NULL;
	}
}

int ticket_in_list(struct ticket_list* l, unsigned t)
{
	struct ticket_node* curr;

	if(l == NULL)
		return 0;
	
	curr = l->head;

	while(curr != NULL)
	{
		if(curr->ticket == t)
			return 1;
		curr = curr->next;
	}
	return 0;
}

void grant_next_alive_ticket(osprd_info_t *d)
{
	while(++(d->ticket_tail))
	{
		if(!ticket_in_list(d->exited_tickets, d->ticket_tail))
			break;
		else 
			remove_from_pid_list(d->exited_tickets,d->ticket_tail);
	}
}

/* The internal representation of our device. */

#define NOSPRD 4
static osprd_info_t osprds[NOSPRD];


// Declare useful helper functions

/*
 * file2osprd(filp)
 *   Given an open file, check whether that file corresponds to an OSP ramdisk.
 *   If so, return a pointer to the ramdisk's osprd_info_t.
 *   If not, return NULL.
 */
static osprd_info_t *file2osprd(struct file *filp);

/*
 * for_each_open_file(task, callback, user_data)
 *   Given a task, call the function 'callback' once for each of 'task's open
 *   files.  'callback' is called as 'callback(filp, user_data)'; 'filp' is
 *   the open file, and 'user_data' is copied from for_each_open_file's third
 *   argument.
 */
static void for_each_open_file(struct task_struct *task,
			       void (*callback)(struct file *filp,
						osprd_info_t *user_data),
			       osprd_info_t *user_data);


/*
 * osprd_process_request(d, req)
 *   Called when the user reads or writes a sector.
 *   Should perform the read or write, as appropriate.
 */
static void osprd_process_request(osprd_info_t *d, struct request *req)
{
	if (!blk_fs_request(req)) {
		end_request(req, 0);
		return;
	}

	unsigned request_type;

	uint8_t *data_ptr;
	
	request_type = rq_data_dir(req);
	
	data_ptr = d->data + req->sector * SECTOR_SIZE;
	
	if(request_type == READ)
	{
		memcpy((void*)req->buffer, (void*)data_ptr, req->current_nr_sectors * SECTOR_SIZE);
	}
	else if(request_type == WRITE)
	{
		memcpy((void*)data_ptr, (void*)req->buffer, req->current_nr_sectors * SECTOR_SIZE);
	}


	eprintk("Should process request...\n");

	end_request(req, 1);
}


// This function is called when a /dev/osprdX file is opened.
// You aren't likely to need to change this.
static int osprd_open(struct inode *inode, struct file *filp)
{
	// Always set the O_SYNC flag. That way, we will get writes immediately
	// instead of waiting for them to get through write-back caches.
	filp->f_flags |= O_SYNC;
	return 0;
}


// This function is called when a /dev/osprdX file is finally closed.
// (If the file descriptor was dup2ed, this function is called only when the
// last copy is closed.)
static int osprd_close_last(struct inode *inode, struct file *filp)
{

	int filp_writable = filp->f_mode & FMODE_WRITE;
	if (filp) {
		osprd_info_t *d = file2osprd(filp);

//		int filp_writable = filp->f_mode & FMODE_WRITE;
		if(filp == NULL)
				return 0;
		else{

			if(!pid_in_list(d->write_list, current->pid) && !pid_in_list(d->read_list, current->pid))
				return -EINVAL;

			else if(filp_writable && pid_in_list(d->write_list, current->pid)) 
				remove_from_pid_list(d->write_list,current->pid);

			else if (!filp_writable && pid_in_list(d->write_list, current->pid)) 
				remove_from_pid_list(d->read_list,current->pid);

			else if ((d->write_list == NULL) && (d->read_list == NULL))
				filp->f_flags &= ~F_OSPRD_LOCKED;

			return 0;
		}
	}

	return 0;
}


/*
 * osprd_lock
 */

/*
 * osprd_ioctl(inode, filp, cmd, arg)
 *   Called to perform an ioctl on the named file.
 */
int osprd_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	osprd_info_t *d = file2osprd(filp);	// device info
	int r = 0;			// return value: initially 0

	// is file open for writing?
	int filp_writable = (filp->f_mode & FMODE_WRITE) != 0;

	unsigned my_ticket;

	// This line avoids compiler warnings; you may remove it.
	(void) filp_writable, (void) d;

	// Set 'r' to the ioctl's return value: 0 on success, negative on error

	if (cmd == OSPRDIOCACQUIRE) {

			osp_spin_lock(&(d->mutex));
			
			my_ticket= d->ticket_head;

			d->ticket_head++;

			if(pid_in_list(d->read_list, current->pid) || pid_in_list(d->write_list, current->pid))
			{
				osp_spin_unlock(&(d->mutex));
				return -EDEADLK;
			}

			osp_spin_unlock(&(d->mutex));

			int temp2;

			if(filp_writable)
			{
				if (d->ticket_tail == my_ticket && d->write_list == NULL)
					temp2 = 1;
				else 
					temp2 = 0;
			}
			else 
			{
				if (d->ticket_tail == my_ticket && d->write_list == NULL)
					temp2 = 1;
				else 
					temp2 = 0;
			}

			if(wait_event_interruptible(d->blockq, temp2))
			{
				if(d->ticket_tail == my_ticket)
					grant_next_alive_ticket(d);
				else 
					add_to_ticket_list(d->exited_tickets, my_ticket);
				return -ERESTARTSYS;
			}
			
			osp_spin_lock(&(d->mutex));
			
			filp->f_flags |= F_OSPRD_LOCKED;
			
			if(filp_writable)
				add_to_pid_list(d->write_list, current->pid);
			else
				add_to_pid_list(d->read_list, current->pid);
			grant_next_alive_ticket(d);
			osp_spin_unlock(&(d->mutex));

			wake_up_all(&(d->blockq));
			return 0;
	}
 
	else if (cmd == OSPRDIOCTRYACQUIRE) 
	{

		// EXERCISE: ATTEMPT to lock the ramdisk.
		//
		// This is just like OSPRDIOCACQUIRE, except it should never
		// block.  If OSPRDIOCACQUIRE would block or return deadlock,
		// OSPRDIOCTRYACQUIRE should return -EBUSY.
		// Otherwise, if we can grant the lock request, return 0.

		// Your code here (instead of the next two lines).
		eprintk("Attempting to try acquire\n");
		r = -ENOTTY;

	} else if (cmd == OSPRDIOCRELEASE) {

		// EXERCISE: Unlock the ramdisk.
		//
		// If the file hasn't locked the ramdisk, return -EINVAL.
		// Otherwise, clear the lock from filp->f_flags, wake up
		// the wait queue, perform any additional accounting steps
		// you need, and return 0.

		// Your code here (instead of the next line).
		r = -ENOTTY;

	} else
		r = -ENOTTY; /* unknown command */
	return r;
}


// Initialize internal fields for an osprd_info_t.

static void osprd_setup(osprd_info_t *d)
{
	/* Initialize the wait queue. */
	init_waitqueue_head(&d->blockq);
	osp_spin_lock_init(&d->mutex);
	d->ticket_head = d->ticket_tail = 0;
	/* Add code here if you add fields to osprd_info_t. */
}


/*****************************************************************************/
/*         THERE IS NO NEED TO UNDERSTAND ANY CODE BELOW THIS LINE!          */
/*                                                                           */
/*****************************************************************************/

// Process a list of requests for a osprd_info_t.
// Calls osprd_process_request for each element of the queue.

static void osprd_process_request_queue(request_queue_t *q)
{
	osprd_info_t *d = (osprd_info_t *) q->queuedata;
	struct request *req;

	while ((req = elv_next_request(q)) != NULL)
		osprd_process_request(d, req);
}


// Some particularly horrible stuff to get around some Linux issues:
// the Linux block device interface doesn't let a block device find out
// which file has been closed.  We need this information.

static struct file_operations osprd_blk_fops;
static int (*blkdev_release)(struct inode *, struct file *);

static int _osprd_release(struct inode *inode, struct file *filp)
{
	if (file2osprd(filp))
		osprd_close_last(inode, filp);
	return (*blkdev_release)(inode, filp);
}

static int _osprd_open(struct inode *inode, struct file *filp)
{
	if (!osprd_blk_fops.open) {
		memcpy(&osprd_blk_fops, filp->f_op, sizeof(osprd_blk_fops));
		blkdev_release = osprd_blk_fops.release;
		osprd_blk_fops.release = _osprd_release;
	}
	filp->f_op = &osprd_blk_fops;
	return osprd_open(inode, filp);
}


// The device operations structure.

static struct block_device_operations osprd_ops = {
	.owner = THIS_MODULE,
	.open = _osprd_open,
	// .release = osprd_release, // we must call our own release
	.ioctl = osprd_ioctl
};


// Given an open file, check whether that file corresponds to an OSP ramdisk.
// If so, return a pointer to the ramdisk's osprd_info_t.
// If not, return NULL.

static osprd_info_t *file2osprd(struct file *filp)
{
	if (filp) {
		struct inode *ino = filp->f_dentry->d_inode;
		if (ino->i_bdev
		    && ino->i_bdev->bd_disk
		    && ino->i_bdev->bd_disk->major == OSPRD_MAJOR
		    && ino->i_bdev->bd_disk->fops == &osprd_ops)
			return (osprd_info_t *) ino->i_bdev->bd_disk->private_data;
	}
	return NULL;
}


// Call the function 'callback' with data 'user_data' for each of 'task's
// open files.

static void for_each_open_file(struct task_struct *task,
		  void (*callback)(struct file *filp, osprd_info_t *user_data),
		  osprd_info_t *user_data)
{
	int fd;
	task_lock(task);
	spin_lock(&task->files->file_lock);
	{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 13)
		struct files_struct *f = task->files;
#else
		struct fdtable *f = task->files->fdt;
#endif
		for (fd = 0; fd < f->max_fds; fd++)
			if (f->fd[fd])
				(*callback)(f->fd[fd], user_data);
	}
	spin_unlock(&task->files->file_lock);
	task_unlock(task);
}


// Destroy a osprd_info_t.

static void cleanup_device(osprd_info_t *d)
{
	wake_up_all(&d->blockq);
	if (d->gd) {
		del_gendisk(d->gd);
		put_disk(d->gd);
	}
	if (d->queue)
		blk_cleanup_queue(d->queue);
	if (d->data)
		vfree(d->data);
}


// Initialize a osprd_info_t.

static int setup_device(osprd_info_t *d, int which)
{
	memset(d, 0, sizeof(osprd_info_t));

	/* Get memory to store the actual block data. */
	if (!(d->data = vmalloc(nsectors * SECTOR_SIZE)))
		return -1;
	memset(d->data, 0, nsectors * SECTOR_SIZE);

	/* Set up the I/O queue. */
	spin_lock_init(&d->qlock);
	if (!(d->queue = blk_init_queue(osprd_process_request_queue, &d->qlock)))
		return -1;
	blk_queue_hardsect_size(d->queue, SECTOR_SIZE);
	d->queue->queuedata = d;

	/* The gendisk structure. */
	if (!(d->gd = alloc_disk(1)))
		return -1;
	d->gd->major = OSPRD_MAJOR;
	d->gd->first_minor = which;
	d->gd->fops = &osprd_ops;
	d->gd->queue = d->queue;
	d->gd->private_data = d;
	snprintf(d->gd->disk_name, 32, "osprd%c", which + 'a');
	set_capacity(d->gd, nsectors);
	add_disk(d->gd);

	/* Call the setup function. */
	osprd_setup(d);

	return 0;
}

static void osprd_exit(void);


// The kernel calls this function when the module is loaded.
// It initializes the 4 osprd block devices.

static int __init osprd_init(void)
{
	int i, r;

	// shut up the compiler
	(void) for_each_open_file;
#ifndef osp_spin_lock
	(void) osp_spin_lock;
	(void) osp_spin_unlock;
#endif

	/* Register the block device name. */
	if (register_blkdev(OSPRD_MAJOR, "osprd") < 0) {
		printk(KERN_WARNING "osprd: unable to get major number\n");
		return -EBUSY;
	}

	/* Initialize the device structures. */
	for (i = r = 0; i < NOSPRD; i++)
		if (setup_device(&osprds[i], i) < 0)
			r = -EINVAL;

	if (r < 0) {
		printk(KERN_EMERG "osprd: can't set up device structures\n");
		osprd_exit();
		return -EBUSY;
	} else
		return 0;
}


// The kernel calls this function to unload the osprd module.
// It destroys the osprd devices.

static void osprd_exit(void)
{
	int i;
	for (i = 0; i < NOSPRD; i++)
		cleanup_device(&osprds[i]);
	unregister_blkdev(OSPRD_MAJOR, "osprd");
}


// Tell Linux to call those functions at init and exit time.
module_init(osprd_init);
module_exit(osprd_exit);
