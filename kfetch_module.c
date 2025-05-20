#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/timekeeping.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <asm/processor.h> // boot_cpu_data
#include <linux/string.h>
#include <linux/sysinfo.h>

#define DEVICE_NAME "kfetch"
#define CLASS_NAME "kfetch_class"

#define KFETCH_NUM_INFO 6
#define KFETCH_RELEASE   (1 << 0)  // Kernel version
#define KFETCH_NUM_CPUS  (1 << 1)  // Number of CPUs
#define KFETCH_CPU_MODEL (1 << 2)  // CPU model
#define KFETCH_MEM       (1 << 3)  // Memory info
#define KFETCH_UPTIME    (1 << 4)  // Uptime
#define KFETCH_NUM_PROCS (1 << 5)  // Number of processes
#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

#define MAX_REQUEST_LEN 64

#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[34m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[36m"

static int major;
static struct class *kfetch_class;
static struct cdev kfetch_cdev;
static dev_t dev_num;

static DEFINE_MUTEX(kfetch_mutex);
static char kfetch_buf[1024];
static char info_request[MAX_REQUEST_LEN] = "";  // String de consulta

static int kfetch_open(struct inode *inode, struct file *file);
static int kfetch_release(struct inode *inode, struct file *file);
static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset);
static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset);

static struct file_operations fops = {
    .open = kfetch_open,
    .release = kfetch_release,
    .read = kfetch_read,
    .write = kfetch_write,
};

// Funções para obter as informações do sistema

static char *get_hostname(void) {
    struct new_utsname *uts = utsname();
    return uts->nodename;
}

static char *get_kernel_version(void) {
    struct new_utsname *uts = utsname();
    return uts->release;
}

static char *get_cpu_info(void) {
    static char cpu_model[128];
    snprintf(cpu_model, sizeof(cpu_model), "%s", boot_cpu_data.x86_model_id);
    return cpu_model;
}

static char *get_memory_info(void) {
    static char mem_buf[64];
    struct sysinfo si;
    si_meminfo(&si);
    snprintf(mem_buf, sizeof(mem_buf), "%lu / %lu MB", si.freeram / 1024 / 1024, si.totalram / 1024 / 1024);
    return mem_buf;
}

static char *get_process_count(void) {
    static char proc_buf[16];
    int count = 0;
    struct task_struct *task;

    for_each_process(task) {
        count++;
    }

    snprintf(proc_buf, sizeof(proc_buf), "%d", count);
    return proc_buf;
}

static char *get_uptime(void) {
    static char uptime_buf[32];
    unsigned long uptime = ktime_get_boottime_seconds() / 60;
    snprintf(uptime_buf, sizeof(uptime_buf), "%lu minutos", uptime);
    return uptime_buf;
}

// Função para verificar se uma chave está presente na string info_request
static bool request_contains(const char *key) {
    char buf[MAX_REQUEST_LEN + 3];  // para "|" + info_request + "|"
    char keybuf[32];
    snprintf(buf, sizeof(buf), "|%s|", info_request);
    snprintf(keybuf, sizeof(keybuf), "|%s|", key);

    if (strstr(buf, keybuf) != NULL)
        return true;
    return false;
}

// Leitura do dispositivo
static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset) {
    int pos = 0;

    if (*offset > 0)
        return 0;

    const char *logo =
        " <(o )___\n"
        "   ( ._> /\n"
        "    `---'\n";

    memset(kfetch_buf, 0, sizeof(kfetch_buf));

    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_YELLOW"%s", logo);
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos,  "%s\n", get_hostname());
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, "%.*s\n", (int)strlen(get_hostname()), "==============================");

    // Se info_request vazia, imprime tudo
    if (strlen(info_request) == 0) {
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Kernel: %s\n" COLOR_RESET, get_kernel_version());
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_CYAN "CPU: %s\n" COLOR_RESET, get_cpu_info());
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_BLUE "CPUs: %d\n" COLOR_RESET, num_online_cpus());
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Mem: %s\n" COLOR_RESET, get_memory_info());
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_YELLOW "Uptime: %s\n" COLOR_RESET, get_uptime());
        pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_RED "Proc: %s\n" COLOR_RESET, get_process_count());
    } else {
        if (request_contains("KERNEL"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Kernel: %s\n" COLOR_RESET, get_kernel_version());

        if (request_contains("CPU"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_CYAN "CPU: %s\n" COLOR_RESET, get_cpu_info());

        if (request_contains("CPUS"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_BLUE "CPUs: %d\n" COLOR_RESET, num_online_cpus());

        if (request_contains("MEM"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Mem: %s\n" COLOR_RESET, get_memory_info());

        if (request_contains("UPTIME"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_YELLOW "Uptime: %s\n" COLOR_RESET, get_uptime());

        if (request_contains("PROC"))
            pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_RED "Proc: %s\n" COLOR_RESET, get_process_count());
    }

    if (copy_to_user(buffer, kfetch_buf, pos))
        return -EFAULT;

    *offset += pos;
    return pos;
}

// Escrita no dispositivo: grava string de consulta
static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset) {
    if (len >= MAX_REQUEST_LEN)
        return -EINVAL;

    if (copy_from_user(info_request, buffer, len))
        return -EFAULT;

    info_request[len] = '\0';

    // Remove \n final se houver
    if (len > 0 && info_request[len - 1] == '\n')
        info_request[len - 1] = '\0';

    pr_info("kfetch_mod: info_request atualizada para '%s'\n", info_request);
    return len;
}

// Abertura do dispositivo
static int kfetch_open(struct inode *inode, struct file *file) {
    if (!mutex_trylock(&kfetch_mutex))
        return -EBUSY;
    return 0;
}

// Liberação do dispositivo
static int kfetch_release(struct inode *inode, struct file *file) {
    mutex_unlock(&kfetch_mutex);
    return 0;
}

// Inicialização do módulo
static int __init kfetch_init(void) {
    alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    major = MAJOR(dev_num);

    cdev_init(&kfetch_cdev, &fops);
    cdev_add(&kfetch_cdev, dev_num, 1);

    kfetch_class = class_create(CLASS_NAME);
    device_create(kfetch_class, NULL, dev_num, NULL, DEVICE_NAME);

    mutex_init(&kfetch_mutex);
    pr_info("kfetch_mod carregado.\n");
    return 0;
}

// Finalização do módulo
static void __exit kfetch_exit(void) {
    mutex_destroy(&kfetch_mutex);
    device_destroy(kfetch_class, dev_num);
    class_unregister(kfetch_class);
    class_destroy(kfetch_class);
    cdev_del(&kfetch_cdev);
    unregister_chrdev_region(dev_num, 1);
    pr_info("kfetch_mod descarregado.\n");
}

module_init(kfetch_init);
module_exit(kfetch_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Módulo do Kernel para recuperar informações do sistema");
