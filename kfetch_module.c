#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/jiffies.h>
#include <linux/timekeeping.h>
#include <linux/mutex.h>

#define DEVICE_NAME "kfetch"
#define CLASS_NAME "kfetch_class"

#define KFETCH_NUM_INFO 6
#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)
#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

// Códigos ANSI para cores
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
static int info_mask = KFETCH_FULL_INFO;

static DEFINE_MUTEX(kfetch_mutex);
static char kfetch_buf[1024];

// Funções do arquivo
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

// Função para obter o nome do host
static char *get_hostname(void) {
    struct new_utsname *uts = utsname();
    return uts->nodename;
}

// Função para obter a versão do kernel
static char *get_kernel_version(void) {
    struct new_utsname *uts = utsname();
    return uts->release;
}

// Função para obter o número de CPUs
static char *get_cpu_info(void) {
    return num_online_cpus();
}

// Função para obter a memória
static char *get_memory_info(void) {
    struct sysinfo si;
    si_meminfo(&si);
    snprintf(kfetch_buf, sizeof(kfetch_buf), "%lu / %lu MB", si.freeram / 1024 / 1024, si.totalram / 1024 / 1024);
    return kfetch_buf;
}

// Função para obter o número de processos
static char *get_process_count(void) {
    snprintf(kfetch_buf, sizeof(kfetch_buf), "%d", num_threads());
    return kfetch_buf;
}

// Função para obter o uptime
static char *get_uptime(void) {
    unsigned long uptime = jiffies_to_msecs(boottime()) / 60000;
    snprintf(kfetch_buf, sizeof(kfetch_buf), "%lu minutos", uptime);
    return kfetch_buf;
}

// Função de leitura
static ssize_t kfetch_read(struct file *filp, char __user *buffer, size_t len, loff_t *offset) {
    int pos = 0;
    struct new_utsname *uts = utsname();
    const char *logo = 
    " <(o )___\n"
    "   ( ._> /\n"
    "    `---'\n";

// Adiciona o logotipo ao buffer
pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, "%s", logo);

// Nome do host
pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_YELLOW "%s\n", get_hostname());
pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, "%.*s\n", (int)strlen(get_hostname()), "==============================");

// Kernel
if (info_mask & KFETCH_RELEASE) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Kernel: %s\n" COLOR_RESET, get_kernel_version());
}

// CPU
if (info_mask & KFETCH_CPU_MODEL) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_CYAN "CPU: %s\n" COLOR_RESET, get_cpu_info());
}

// Número de CPUs
if (info_mask & KFETCH_NUM_CPUS) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_BLUE "CPUs: %d\n" COLOR_RESET, num_online_cpus());
}

// Memória
if (info_mask & KFETCH_MEM) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_GREEN "Mem: %s\n" COLOR_RESET, get_memory_info());
}

// Uptime
if (info_mask & KFETCH_UPTIME) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_YELLOW "Uptime: %s\n" COLOR_RESET, get_uptime());
}

// Número de processos
if (info_mask & KFETCH_NUM_PROCS) {
    pos += scnprintf(kfetch_buf + pos, sizeof(kfetch_buf) - pos, COLOR_RED "Proc: %s\n" COLOR_RESET, get_process_count());
}

// Copiar dados para o usuário
if (copy_to_user(buffer, kfetch_buf, pos)) {
    return -EFAULT;
}

return pos;
}

// Função de escrita (atualizar máscara)
static ssize_t kfetch_write(struct file *filp, const char __user *buffer, size_t len, loff_t *offset) {
    int new_mask;

    if (copy_from_user(&new_mask, buffer, sizeof(int))) {
        return -EFAULT;
    }

    info_mask = new_mask;
    return sizeof(int);
}

// Função open
static int kfetch_open(struct inode *inode, struct file *file) {
    if (!mutex_trylock(&kfetch_mutex)) {
        return -EBUSY;
    }
    return 0;
}

// Função release
static int kfetch_release(struct inode *inode, struct file *file) {
    mutex_unlock(&kfetch_mutex);
    return 0;
}

// Função de inicialização
static int __init kfetch_init(void) {
    alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    major = MAJOR(dev_num);

    cdev_init(&kfetch_cdev, &fops);
    cdev_add(&kfetch_cdev, dev_num, 1);

    kfetch_class = class_create(THIS_MODULE, CLASS_NAME);
    device_create(kfetch_class, NULL, dev_num, NULL, DEVICE_NAME);

    mutex_init(&kfetch_mutex);

    pr_info("kfetch_mod carregado.\n");
    return 0;
}

// Função de finalização
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
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo do Kernel para recuperar informações do sistema");

'''Testando o Módulo:
Compile o módulo.

Carregue o módulo com insmod kfetch_mod.ko.

Acesse o dispositivo /dev/kfetch para ler e escrever com cat /dev/kfetch ou echo <máscara> > /dev/kfetch.'''