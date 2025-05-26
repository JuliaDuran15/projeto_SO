/*O cálculo de risco para cada critério é feito usando a normalização, onde os valores são convertidos para uma escala de 0 a 1000, e esses valores são ponderados de acordo com a sua importância no cálculo final. Vamos detalhar cada critério.
1. CPU (20%):

    Cálculo: O tempo de CPU utilizado pelo processo é obtido somando os tempos de CPU no modo usuário (utime) e no modo kernel (stime), que são valores armazenados na estrutura task_struct. A soma desses tempos (cpu_time) é então normalizada em relação a um valor de referência (CPU_TIME_THRESHOLD).

    Normalização: O valor é normalizado dividindo o tempo de CPU consumido pelo processo por um limite de referência, que é o CPU_TIME_THRESHOLD. Isso gera um valor na faixa de 0 a 1000.

        Se o valor de cpu_norm for maior que 1000, ele é limitado a 1000 (máximo).

    Classificação: Se o valor normalizado de CPU exceder um limite, o processo é considerado de alto risco. Caso contrário, ele é ponderado junto aos outros critérios.

2. Trocas de Contexto (nvcsw e nivcsw) (10%):

    Cálculo: As trocas de contexto voluntárias (nvcsw) e involuntárias (nivcsw) são extraídas da estrutura task_struct para cada processo.

        Voluntárias (nvcsw): Indicam quantas vezes o processo voluntariamente cedeu a CPU para outro processo.

        Involuntárias (nivcsw): Indicam quantas vezes o processo foi interrompido pela política de escalonamento do kernel.

    Normalização: O número total de trocas de contexto (soma de nvcsw e nivcsw) é normalizado com base em um limite de referência (NVCSW_THRESHOLD + NIVCSW_THRESHOLD), de modo que valores maiores recebem uma pontuação mais alta.

        O valor é normalizado para a faixa de 0 a 1000, e valores superiores a 1000 são limitados.

3. Leitura e Escrita em Disco (15%):

    Cálculo: O número total de bytes lidos (read_bytes) e escritos (write_bytes) em disco é recuperado da estrutura task_struct (se a configuração do kernel permitir, como CONFIG_TASK_IO_ACCOUNTING).

    Normalização: A soma dos bytes lidos e escritos é somada e normalizada em relação a um limite de referência (IO_BYTES_THRESHOLD), gerando um valor na faixa de 0 a 1000. Se o valor exceder 1000, ele é limitado.

4. Rede (25%):

    Cálculo: O critério de rede verifica se o processo tem sockets abertos. A função has_open_socket percorre os descritores de arquivos do processo e verifica se algum deles é um socket.

    Normalização: Se o processo tiver ao menos um socket, ele recebe uma pontuação de 1000. Caso contrário, a pontuação é 0.

5. Privilégios (20%):

    Cálculo: O critério de privilégios verifica se o processo está sendo executado como root (UID 0). O campo task->cred->uid.val é utilizado para verificar se o UID do processo é 0.

    Normalização: Se o processo for root (UID 0), ele recebe uma pontuação de 1000. Caso contrário, a pontuação é 0.

6. Uptime (10%):

    Cálculo: O tempo de vida do processo desde que ele foi iniciado é calculado a partir do campo task->start_time, comparado com o tempo atual do sistema obtido a partir da função ktime_get_boottime.

    Normalização: O uptime do processo é normalizado com base no tempo de vida de 1000 segundos. Se o tempo de vida for superior a 1000 segundos, ele recebe a pontuação máxima de 1000.

7. Origem Suspeita (10%):

    Cálculo: O critério de origem suspeita verifica se o caminho do executável do processo está localizado fora dos diretórios tradicionais (/usr ou /bin). A função get_exe_path é usada para obter o caminho do executável.

    Normalização: Se o caminho do executável estiver fora de /usr ou /bin, ele recebe uma pontuação de 1000 (considerado suspeito).

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
        return simple_read_from_buffer(buf, count, pos, "No PID set. Use echo <pid> > /proc/process_risk/risk_score\n", 58);

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


/*#include <linux/module.h>: Importa as funções e macros necessárias para definir o módulo do kernel. Ele permite carregar e descarregar módulos no kernel.

#include <linux/kernel.h>: Oferece funções e definições essenciais para o funcionamento do kernel, como funções de log (pr_info para imprimir mensagens de log).

#include <linux/init.h>: Necessário para as macros module_init e module_exit, que indicam as funções a serem chamadas quando o módulo é carregado ou descarregado.

#include <linux/fs.h>: Importa as estruturas e funções relacionadas ao gerenciamento de arquivos. A estrutura files_struct está definida aqui, usada para manipular os descritores de arquivos de um processo.

#include <linux/file.h> e #include <linux/fdtable.h>: Usados para manipular e acessar a tabela de arquivos (fdtable) e os descritores de arquivos associados aos processos. A função files_fdtable está definida em fdtable.h.

#include <linux/proc_fs.h>: Fornece a interface para criar arquivos em /proc, o que permite interagir com o sistema de arquivos proc. Isso será usado para criar a interface de leitura e escrita no /proc para exibir o risco do processo.

#include <linux/uaccess.h>: Necessário para realizar operações de leitura e escrita entre o espaço de usuário e o espaço do kernel.

#include <linux/sched.h>: Contém as funções e estruturas necessárias para interagir com o escalonador de processos do kernel, incluindo a estrutura task_struct, que armazena informações sobre cada processo.

#include <linux/seq_file.h>: Usado para criar arquivos seq (sequenciais), que são ideais para leitura de dados estruturados, como a exposição dos resultados no /proc.

#include <linux/pid.h>: Usado para manipulação de PIDs (IDs de processos), necessário para identificar e acessar os processos no sistema.

#define PROC_DIR_NAME "process_risk" e #define PROC_FILE_NAME "risk_score": Define os nomes do diretório e do arquivo que serão criados no /proc. O diretório será /proc/process_risk, e o arquivo dentro dele será /proc/process_risk/risk_score.

#define CPU_TIME_THRESHOLD 100000: Define um limiar de tempo de CPU (em jiffies) acima do qual o processo será considerado de risco maior em relação ao uso de CPU.

#define NVCSW_THRESHOLD 1000 e #define NIVCSW_THRESHOLD 1000: Definem os limites para as trocas de contexto voluntárias (nvcsw) e involuntárias (nivcsw). Esses limites são usados para determinar se um processo teve muitas trocas de contexto, o que pode indicar um comportamento anômalo.

#define IO_BYTES_THRESHOLD 1000000: Define um limite para o número total de bytes lidos e escritos em disco. Isso é usado para classificar o processo como de maior risco se ele estiver fazendo muitas operações de I/O.

Pesos das métricas:

    CPU_WEIGHT_MIL, SYS_CALL_WEIGHT_MIL, IO_WEIGHT_MIL: Esses pesos são atribuídos a cada critério (CPU, chamadas de sistema e I/O) ao calcular a pontuação total. Eles determinam a importância relativa de cada critério na pontuação final do risco.
*/