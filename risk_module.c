/*
1. Coleta de Métricas
- Uso de CPU: obtido de `task->utime` e `task->stime`.
- Atividade de E/S: removido por falta de acesso direto no kernel.

2. Definição do Algoritmo de Pontuação
- CPU: baseia-se no tempo total de CPU consumido pelo processo.

3. Classificação
- Baixo, Médio ou Alto risco com base em thresholds definidos.




*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/pid.h>

#define PROC_DIR_NAME "process_risk"
#define PROC_FILE_NAME "risk_score"

#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RED    "\033[31m"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

static pid_t target_pid = -1;

// Avalia risco com base no tempo de CPU
static int calculate_risk(struct task_struct *task) {
    unsigned long cpu_time = task->utime + task->stime;
    unsigned long cpu_threshold = 100000;

    if (cpu_time > cpu_threshold)
        return 3; // Alto
    else if (cpu_time > cpu_threshold / 2)
        return 2; // Médio
    else
        return 1; // Baixo
}

// Leitura do /proc
static ssize_t risk_score_read(struct file *file, char __user *buf, size_t count, loff_t *pos) {
    char result[128];
    int len = 0;
    struct task_struct *task;
    struct pid *pid_struct;
    int risk_score;

    if (*pos > 0)
        return 0;

    if (target_pid <= 0)
        return simple_read_from_buffer(buf, count, pos, "No PID set. Use echo <pid> > /proc/process_risk/risk_score\n", 58);

    pid_struct = find_get_pid(target_pid);
    task = pid_task(pid_struct, PIDTYPE_PID);

    if (!task) {
        len = snprintf(result, sizeof(result), "PID %d not found\n", target_pid);
        return simple_read_from_buffer(buf, count, pos, result, len);
    }

    risk_score = calculate_risk(task);

    switch (risk_score) {
        case 1:
            len = snprintf(result, sizeof(result), COLOR_GREEN "PID %d - Risk: Low\n" COLOR_RESET, target_pid);
            break;
        case 2:
            len = snprintf(result, sizeof(result), COLOR_YELLOW "PID %d - Risk: Medium\n" COLOR_RESET, target_pid);
            break;
        case 3:
            len = snprintf(result, sizeof(result), COLOR_RED "PID %d - Risk: High\n" COLOR_RESET, target_pid);
            break;
        default:
            len = snprintf(result, sizeof(result), "PID %d - Risk: Unknown\n", target_pid);
            break;
    }

    return simple_read_from_buffer(buf, count, pos, result, len);
}

// Escrita no /proc: define qual PID avaliar
static ssize_t risk_score_write(struct file *file, const char __user *buffer, size_t len, loff_t *pos) {
    char input[16];

    if (len == 0 || len >= sizeof(input))
        return -EINVAL;

    if (copy_from_user(input, buffer, len))
        return -EFAULT;

    input[len] = '\0';  // garante terminação da string

    if (kstrtoint(strim(input), 10, &target_pid) != 0)
        return -EINVAL;

    printk(KERN_INFO "PID recebido: %d\n", target_pid);
    return len;
}

// Interface para o /proc
static const struct proc_ops risk_score_ops = {
    .proc_read = risk_score_read,
    .proc_write = risk_score_write,
};

// Inicialização do módulo
static int __init risk_module_init(void) {
    proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!proc_dir) {
        printk(KERN_ERR "Failed to create /proc/%s\n", PROC_DIR_NAME);
        return -ENOMEM;
    }

    proc_file = proc_create(PROC_FILE_NAME, 0666, proc_dir, &risk_score_ops);
    if (!proc_file) {
        printk(KERN_ERR "Failed to create /proc/%s/%s\n", PROC_DIR_NAME, PROC_FILE_NAME);
        remove_proc_entry(PROC_DIR_NAME, NULL);
        return -ENOMEM;
    }

    printk(KERN_INFO "Risk score module loaded\n");
    return 0;
}

// Finalização do módulo
static void __exit risk_module_exit(void) {
    remove_proc_entry(PROC_FILE_NAME, proc_dir);
    remove_proc_entry(PROC_DIR_NAME, NULL);
    printk(KERN_INFO "Risk score module unloaded\n");
}

module_init(risk_module_init);
module_exit(risk_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo de Avaliação de Risco baseado em tempo de CPU com seleção de PID");
