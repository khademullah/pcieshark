/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/delay.h>

// Simple FPGA PCIe TLP Generator Device Driver
// Minimal working implementation for open source TLP generation

#define DEVICE_NAME "fpga_pcie"
#define FPGA_BAR_SIZE (4 * 1024 * 1024)  // 4MB simulated BAR

// FPGA register offsets (matching backend_fpga.c)
#define FPGA_REG_COMMAND    0x0000
#define FPGA_REG_TLP_TYPE   0x0004
#define FPGA_REG_ADDRESS    0x0008
#define FPGA_REG_LENGTH     0x000C
#define FPGA_REG_DATA       0x1000

// Commands and status
#define CMD_SEND_TLP        0x01
#define CMD_RESET           0x02
#define STATUS_READY        0x00
#define STATUS_BUSY         0x01
#define STATUS_COMPLETE     0x02
#define STATUS_ERROR        0xFF

static int major_number;
static struct cdev cdev;
static struct class *fpga_class = NULL;
static struct device *fpga_device = NULL;

// Simulated FPGA registers
static uint32_t *fpga_regs = NULL;

static int fpga_open(struct inode *inode, struct file *file) {
    pr_info("FPGA TLP Generator device opened\n");
    return 0;
}

static int fpga_release(struct inode *inode, struct file *file) {
    pr_info("FPGA TLP Generator device closed\n");
    return 0;
}

static ssize_t fpga_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
    if (*offset >= FPGA_BAR_SIZE)
        return 0;

    size_t to_read = min(count, (size_t)(FPGA_BAR_SIZE - *offset));

    if (copy_to_user(buf, (char *)fpga_regs + *offset, to_read))
        return -EFAULT;

    *offset += to_read;
    return to_read;
}

static ssize_t fpga_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    if (*offset >= FPGA_BAR_SIZE)
        return -EINVAL;

    size_t to_write = min(count, (size_t)(FPGA_BAR_SIZE - *offset));

    if (copy_from_user((char *)fpga_regs + *offset, buf, to_write))
        return -EFAULT;

    // Handle special register writes
    if (*offset <= FPGA_REG_COMMAND && *offset + to_write > FPGA_REG_COMMAND) {
        uint32_t cmd = fpga_regs[FPGA_REG_COMMAND / 4];

        if (cmd == CMD_SEND_TLP) {
            // Simulate TLP transmission
            uint32_t tlp_type = fpga_regs[FPGA_REG_TLP_TYPE / 4];
            uint32_t address = fpga_regs[FPGA_REG_ADDRESS / 4];
            uint32_t length = fpga_regs[FPGA_REG_LENGTH / 4];

            pr_info("FPGA: Sending TLP - Type: %d, Addr: 0x%08x, Len: %d bytes",
                    tlp_type, address, length);

            // Simulate transmission delay
            fpga_regs[FPGA_REG_COMMAND / 4] = STATUS_BUSY;
            schedule_delayed_work(&tlp_complete_work, msecs_to_jiffies(5));

        } else if (cmd == CMD_RESET) {
            // Reset all registers
            memset(fpga_regs, 0, FPGA_BAR_SIZE);
            fpga_regs[FPGA_REG_COMMAND / 4] = STATUS_READY;
            pr_info("FPGA: Reset completed");
        }
    }

    *offset += to_write;
    return to_write;
}

static loff_t fpga_llseek(struct file *file, loff_t offset, int whence) {
    loff_t new_offset;

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = file->f_pos + offset;
            break;
        case SEEK_END:
            new_offset = FPGA_BAR_SIZE + offset;
            break;
        default:
            return -EINVAL;
    }

    if (new_offset < 0 || new_offset > FPGA_BAR_SIZE)
        return -EINVAL;

    file->f_pos = new_offset;
    return new_offset;
}

static struct file_operations fops = {
    .open = fpga_open,
    .release = fpga_release,
    .read = fpga_read,
    .write = fpga_write,
    .llseek = fpga_llseek,
    .owner = THIS_MODULE,
};

static void tlp_complete_work(struct work_struct *work) {
    // Mark TLP transmission as complete
    fpga_regs[FPGA_REG_COMMAND / 4] = STATUS_COMPLETE;
    pr_info("FPGA: TLP transmission completed");

    // Schedule ready status after a brief delay
    schedule_delayed_work(&tlp_ready_work, msecs_to_jiffies(1));
}

static void tlp_ready_work(struct work_struct *work) {
    fpga_regs[FPGA_REG_COMMAND / 4] = STATUS_READY;
    pr_info("FPGA: Ready for next TLP");
}

static DECLARE_DELAYED_WORK(tlp_complete_work, tlp_complete_work);
static DECLARE_DELAYED_WORK(tlp_ready_work, tlp_ready_work);

static int __init fpga_init(void) {
    // Allocate memory for simulated FPGA registers
    fpga_regs = kzalloc(FPGA_BAR_SIZE, GFP_KERNEL);
    if (!fpga_regs) {
        pr_err("Failed to allocate FPGA register memory\n");
        return -ENOMEM;
    }

    // Initialize status as ready
    fpga_regs[FPGA_REG_COMMAND / 4] = STATUS_READY;

    // Register character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("Failed to register character device\n");
        kfree(fpga_regs);
        return major_number;
    }

    // Create device class
    fpga_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(fpga_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(fpga_regs);
        return PTR_ERR(fpga_class);
    }

    // Create device
    fpga_device = device_create(fpga_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(fpga_device)) {
        class_destroy(fpga_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(fpga_regs);
        return PTR_ERR(fpga_device);
    }

    pr_info("FPGA TLP Generator device registered (major %d)\n", major_number);
    pr_info("Device file: /dev/%s\n", DEVICE_NAME);
    pr_info("This is a SIMULATION driver - replace with real FPGA hardware driver\n");
    return 0;
}

static void __exit fpga_exit(void) {
    cancel_delayed_work_sync(&tlp_complete_work);
    cancel_delayed_work_sync(&tlp_ready_work);

    device_destroy(fpga_class, MKDEV(major_number, 0));
    class_destroy(fpga_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(fpga_regs);
    pr_info("FPGA TLP Generator device unregistered\n");
}

module_init(fpga_init);
module_exit(fpga_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Open Source PCIe TLP Generator");
MODULE_DESCRIPTION("Minimal FPGA PCIe TLP Generator Device Driver");
MODULE_VERSION("1.0");

static int fpga_release(struct inode *inode, struct file *file) {
    pr_info("FPGA device closed\n");
    return 0;
}

static ssize_t fpga_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
    if (*offset >= FPGA_BAR_SIZE)
        return 0;

    size_t to_read = min(count, (size_t)(FPGA_BAR_SIZE - *offset));

    if (copy_to_user(buf, (char *)fpga_regs + *offset, to_read))
        return -EFAULT;

    *offset += to_read;
    return to_read;
}

static ssize_t fpga_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    if (*offset >= FPGA_BAR_SIZE)
        return -EINVAL;

    size_t to_write = min(count, (size_t)(FPGA_BAR_SIZE - *offset));

    if (copy_from_user((char *)fpga_regs + *offset, buf, to_write))
        return -EFAULT;

    // Handle TLP send command
    if (*offset <= FPGA_REG_TLP_CTRL && *offset + to_write > FPGA_REG_TLP_CTRL) {
        uint32_t ctrl = fpga_regs[FPGA_REG_TLP_CTRL / 4];
        if (ctrl & TLP_CTRL_SEND) {
            // Simulate TLP transmission
            pr_info("FPGA: TLP send triggered - Type: 0x%x, Length: %d DW, Addr: 0x%llx\n",
                    fpga_regs[FPGA_REG_TLP_FMT_TYPE / 4] & 0xFF,
                    fpga_regs[FPGA_REG_TLP_LENGTH / 4],
                    ((uint64_t)fpga_regs[FPGA_REG_TLP_ADDR_HI / 4] << 32) |
                    fpga_regs[FPGA_REG_TLP_ADDR_LO / 4]);

            // Set busy, then complete after delay
            fpga_regs[FPGA_REG_TLP_STATUS / 4] |= TLP_STATUS_BUSY;
            fpga_regs[FPGA_REG_TLP_STATUS / 4] &= ~TLP_STATUS_COMPLETE;

            // Simulate transmission delay and completion
            schedule_delayed_work(&complete_work, msecs_to_jiffies(10));
        }

        if (ctrl & TLP_CTRL_RESET) {
            // Reset all registers
            memset(fpga_regs, 0, FPGA_BAR_SIZE);
            pr_info("FPGA: Reset performed\n");
        }
    }

    *offset += to_write;
    return to_write;
}

static loff_t fpga_llseek(struct file *file, loff_t offset, int whence) {
    loff_t new_offset;

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = file->f_pos + offset;
            break;
        case SEEK_END:
            new_offset = FPGA_BAR_SIZE + offset;
            break;
        default:
            return -EINVAL;
    }

    if (new_offset < 0 || new_offset > FPGA_BAR_SIZE)
        return -EINVAL;

    file->f_pos = new_offset;
    return new_offset;
}

static struct file_operations fops = {
    .open = fpga_open,
    .release = fpga_release,
    .read = fpga_read,
    .write = fpga_write,
    .llseek = fpga_llseek,
    .owner = THIS_MODULE,
};

static void complete_tlp_work(struct work_struct *work) {
    // Mark transmission as complete
    fpga_regs[FPGA_REG_TLP_STATUS / 4] &= ~TLP_STATUS_BUSY;
    fpga_regs[FPGA_REG_TLP_STATUS / 4] |= TLP_STATUS_COMPLETE;
    pr_info("FPGA: TLP transmission completed\n");
}

static DECLARE_DELAYED_WORK(complete_work, complete_tlp_work);

static int __init fpga_init(void) {
    // Allocate memory for simulated FPGA BAR
    fpga_regs = kzalloc(FPGA_BAR_SIZE, GFP_KERNEL);
    if (!fpga_regs) {
        pr_err("Failed to allocate FPGA BAR memory\n");
        return -ENOMEM;
    }

    fpga_data_buf = (uint8_t *)fpga_regs + FPGA_REG_TLP_DATA;

    // Register character device
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("Failed to register character device\n");
        kfree(fpga_regs);
        return major_number;
    }

    // Create device class
    fpga_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(fpga_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(fpga_regs);
        return PTR_ERR(fpga_class);
    }

    // Create device
    fpga_device = device_create(fpga_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(fpga_device)) {
        class_destroy(fpga_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(fpga_regs);
        return PTR_ERR(fpga_device);
    }

    pr_info("FPGA PCIe TLP Generator device registered (major %d)\n", major_number);
    pr_info("Device file: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit fpga_exit(void) {
    cancel_delayed_work_sync(&complete_work);
    device_destroy(fpga_class, MKDEV(major_number, 0));
    class_destroy(fpga_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(fpga_regs);
    pr_info("FPGA PCIe TLP Generator device unregistered\n");
}

module_init(fpga_init);
module_exit(fpga_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("libpcapcie");
MODULE_DESCRIPTION("Simulated FPGA PCIe TLP Generator Device Driver");
MODULE_VERSION("1.0");