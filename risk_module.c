/*O cálculo de risco para cada processo é realizado através da normalização de métricas extraídas do kernel, convertendo-as para uma escala de 0 a 1000. Esses valores normalizados são então ponderados de acordo com seu impacto no score final. Abaixo, detalhamos cada critério e seu peso real no cálculo final de risco.
1. Uso de CPU (30%)

    Cálculo: O tempo de CPU é obtido somando os tempos no modo usuário (utime) e no modo kernel (stime), ambos presentes na estrutura task_struct.

    Normalização: O valor é dividido por um limite de referência (CPU_TIME_THRESHOLD) e multiplicado por 1000. Se o valor exceder 1000, é limitado.

    Interpretação: Quanto maior o uso de CPU, maior o risco. Este é o critério de maior peso na análise final.

2. Chamadas de Sistema (18%)

    Cálculo: Soma das trocas de contexto voluntárias (nvcsw) e involuntárias (nivcsw) extraídas de task_struct.

    Normalização: O total é comparado a um limite (soma de NVCSW_THRESHOLD e NIVCSW_THRESHOLD), resultando em uma pontuação de 0 a 1000, com limite superior de 1000.

    Interpretação: Muitos context switches podem indicar comportamento incomum ou carga elevada.

3. Operações de I/O (12%)

    Cálculo: Soma dos bytes lidos (read_bytes) e escritos (write_bytes) em disco.

    Normalização: Dividido pelo IO_BYTES_THRESHOLD e limitado a 1000.

    Interpretação: Processos que fazem leituras/escritas intensivas em disco podem ser suspeitos, dependendo do contexto.

4. Atividades de Rede (15%)

    Cálculo: Verifica se o processo possui algum socket aberto, analisando os descritores de arquivos.

    Normalização: Se houver ao menos um socket, a pontuação é 1000. Caso contrário, é 0.

    Interpretação: A presença de sockets pode indicar comunicação ativa, o que aumenta o risco em certos contextos.

5. Privilégios Elevados (12%)

    Cálculo: Verifica se o processo está executando como root (UID 0), usando o campo task->cred->uid.val.

    Normalização: UID 0 recebe 1000 pontos; outros valores recebem 0.

    Interpretação: Processos com privilégios de root têm maior capacidade de causar danos ao sistema.

6. Uptime (6%)

    Cálculo: Tempo de vida do processo, baseado em task->start_time e o tempo atual do sistema (ktime_get_boottime).

    Normalização: Tempo até 1000 segundos é convertido proporcionalmente até 1000. Acima disso, recebe 1000.

    Interpretação: Processos recém-criados são mais suspeitos, enquanto os antigos são considerados mais confiáveis.

7. Caminho do Executável Suspeito (6%)

    Cálculo: Através da função get_exe_path, obtém-se o caminho do executável. Se estiver fora de /usr ou /bin, é considerado incomum.

    Normalização: Caminhos suspeitos recebem 1000 pontos; os demais, 0.

    Interpretação: Executáveis em diretórios não convencionais podem ser indícios de comportamento malicioso.
    
Pontuação Final:

A pontuação final é calculada a partir da média ponderada das métricas normalizadas. 
Ponderação: Cada critério recebe um peso específico:

Uso de CPU: 30%

Chamadas de sistema (syscalls): 18%

Operações de I/O: 12%

Atividades de rede: 15%

Privilégios elevados: 12%

Tempo de atividade do processo (uptime): 6%

Caminho de execução suspeito: 6%

Classificação:

    Alto Risco: Se a pontuação for superior a 750.

    Médio Risco: Se a pontuação estiver entre 400 e 750.

    Baixo Risco: Se a pontuação for inferior a 400.
    
    Conclusão:a abordagem com normalização e ponderação é preferível, especialmente para sistemas mais complexos onde o comportamento dos processos pode variar amplamente.*/


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>        // Para files_struct
#include <linux/file.h>      // Para fdtable e files_fdtable
#include <linux/fdtable.h>   // Para arquivos de FD
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

#define CPU_TIME_THRESHOLD 100000
#define NVCSW_THRESHOLD 1000
#define NIVCSW_THRESHOLD 1000
#define IO_BYTES_THRESHOLD 1000000

#define CPU_WEIGHT_MIL      500
#define SYS_CALL_WEIGHT_MIL 300
#define IO_WEIGHT_MIL       200

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

static pid_t target_pid = -1;

// Função que verifica se o processo tem sockets abertos
static bool has_open_socket(struct task_struct *task) {
    struct fdtable *fdt;
    struct files_struct *files;
    struct file **fd;
    int i;
    bool found = false;

    rcu_read_lock(); //leitura dos dados sem interferencia 
    files = task->files; //Obtém os descritores de arquivos associados ao processo
    if (!files) {
        rcu_read_unlock();
        return false;
    }

    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);  // Obtém a tabela de arquivos do processo
    fd = fdt->fd;  // Array de descritores de arquivos

    for (i = 0; i < fdt->max_fds; i++) {
        struct file *file = fd[i];
        if (file && S_ISSOCK(file->f_path.dentry->d_inode->i_mode)) {
            found = true;
            break;
        }
    }

    spin_unlock(&files->file_lock);
    rcu_read_unlock();

    return found;
}

// Função que obtém o caminho do executável
static int get_exe_path(struct task_struct *task, char *buf, int buflen) {
    struct file *exe;
    char *path;

    if (!task->mm || !task->mm->exe_file) //Verifica se o processo tem um espaço de memória e um arquivo executável
        return -1;

    exe = task->mm->exe_file;
    path = d_path(&exe->f_path, buf, buflen);

    if (IS_ERR(path))
        return -1;

    return 0;
}

// Função que calcula o risco baseado em CPU, chamadas de sistema e I/O
static int calculate_risk_enhanced(struct task_struct *task) {
    // Soma de tempo CPU (jiffies)
    unsigned long cpu_time = task->utime + task->stime;

    // Trocas de contexto voluntárias e involuntárias
    unsigned long nvcsw = task->nvcsw;
    unsigned long nivcsw = task->nivcsw;

    // Bytes I/O (se disponível)
    u64 read_bytes = 0;
    u64 write_bytes = 0;
#ifdef CONFIG_TASK_IO_ACCOUNTING
    read_bytes = task->ioac.read_bytes;
    write_bytes = task->ioac.write_bytes;
#endif
    u64 total_io_bytes = read_bytes + write_bytes;

    // Normalizações para escala de 0 a 1000 (mil)
    unsigned long cpu_norm = (cpu_time * 1000) / CPU_TIME_THRESHOLD;
    if (cpu_norm > 1000) cpu_norm = 1000;

    unsigned long sys_calls_norm = ((nvcsw + nivcsw) * 1000) / (NVCSW_THRESHOLD + NIVCSW_THRESHOLD);
    if (sys_calls_norm > 1000) sys_calls_norm = 1000;

    unsigned long io_norm = (total_io_bytes * 1000) / IO_BYTES_THRESHOLD;
    if (io_norm > 1000) io_norm = 1000;

    // Cálculo ponderado do score total (peso para cada métrica)
    unsigned long score_mil = (cpu_norm * CPU_WEIGHT_MIL
                            + sys_calls_norm * SYS_CALL_WEIGHT_MIL
                            + io_norm * IO_WEIGHT_MIL) / 1000;

    // Critério de Rede (25%)
    int has_socket = has_open_socket(task); // Função que verifica se o processo tem sockets abertos
    unsigned long net_score = has_socket ? 1000 : 0; // Rede é 1000 se houver sockets

    // Critério de Privilegios (20%)
    unsigned long priv_score = (task->cred->uid.val == 0) ? 1000 : 0; // Privilegios de root (UID == 0)

    // Critério de Uptime (10%)
    u64 start_time_ns = task->start_time;
    u64 now_ns = ktime_to_ns(ktime_get_boottime());
    u64 age_sec = div_u64(now_ns - start_time_ns, NSEC_PER_SEC);
    unsigned long uptime_score = (age_sec > 1000) ? 1000 : (age_sec * 1000) / 1000; // Até 1000 segundos de uptime

    // Critério de Origem Suspeita (10%)
    char path_buf[512];
    unsigned long path_score = 0;
    if (get_exe_path(task, path_buf, sizeof(path_buf)) == 0) {
        if (strncmp(path_buf, "/usr", 4) != 0 && strncmp(path_buf, "/bin", 4) != 0) {
            path_score = 1000; // Origem suspeita
        }
    }

    // Atualiza o score final com os novos critérios
    score_mil = (score_mil * 1000 + net_score * 250 + priv_score * 200 + uptime_score * 100 + path_score * 100) / 1650;

    // Classificação final em níveis
    if (score_mil > 750)
        return 3; // Alto risco
    else if (score_mil > 400)
        return 2; // Médio risco
    else
        return 1; // Baixo risco
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
        return simple_read_from_buffer(buf, count, pos, "No PID set. Use echo <pid> > /proc/process_risk/risk_score\n", 60);

    pid_struct = find_get_pid(target_pid);
    task = pid_task(pid_struct, PIDTYPE_PID);

    if (!task) {
        len = snprintf(result, sizeof(result), "PID %d not found\n", target_pid);
        return simple_read_from_buffer(buf, count, pos, result, len);
    }

    risk_score = calculate_risk_enhanced(task);

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


