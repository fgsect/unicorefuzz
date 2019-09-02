#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROCFS_NAME       "buffer10"
#define PROCFS_MAX_SIZE   10

struct proc_dir_entry *entry;
static char procfs_buffer[PROCFS_MAX_SIZE];

static ssize_t write_callback(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
  char local_buffer[PROCFS_MAX_SIZE*2];
  char small_local_buffer[PROCFS_MAX_SIZE];
  //char *buffer = kmalloc(PROCFS_MAX_SIZE, GFP_KERNEL);
  copy_from_user(local_buffer, ubuf, PROCFS_MAX_SIZE*2);
  if(local_buffer[0] == 'A')
  {
    //strcpy(buffer, local_buffer);
    strcpy(small_local_buffer, local_buffer);
    strcpy(procfs_buffer, local_buffer);
  }
  else if(local_buffer[0] == 'B')
  {
    strcpy(procfs_buffer, local_buffer);
  }
  else if(local_buffer[0] == 'C')
  {
    strcpy(small_local_buffer, local_buffer);
  }
  //kfree(buffer);
  return count;
}

static ssize_t read_callback(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
  return 0;
}

static struct file_operations ops =
{
	.owner = THIS_MODULE,
	.read = read_callback,
	.write = write_callback,
};

static int simple_init(void)
{
  entry = proc_create(PROCFS_NAME, 0644, NULL, &ops);
  printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
  return 0;
}

static void simple_cleanup(void)
{
  proc_remove(entry);
  printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(simple_init);
module_exit(simple_cleanup);
MODULE_LICENSE("GPL");
