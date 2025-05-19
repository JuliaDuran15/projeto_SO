# Módulos de Kernel: `kfetch_module` e `risk_module`

Este projeto contém dois módulos de kernel desenvolvidos para Linux:

- **`kfetch_module`**: Imita o comportamento de ferramentas como `neofetch`, exibindo informações do sistema no dispositivo `/dev/kfetch`.
- **`risk_module`**: Avalia o risco de um processo específico com base no tempo de uso da CPU. A interação é feita via `/proc/process_risk/risk_score`.

---

## 📦 Arquivos

- `kfetch_module.c` — Módulo que fornece informações do sistema via `/dev/kfetch`.
- `risk_module.c` — Módulo que permite a leitura e escrita de avaliação de risco por PID.
- `Makefile` — Compila ambos os módulos (`.ko`).

---

## 🚀 Como compilar e instalar

1. Compilar os módulos

```bash
make clean && make
```
2. Carregar os módulos
```bash
sudo insmod kfetch_module.ko
sudo insmod risk_module.ko
```
Verifique se /dev/kfetch e /proc/process_risk/risk_score foram criados:
```bash
ls /dev/kfetch
ls /proc/process_risk/risk_score
```

# 🖥️ Uso dos módulos

## 📘 kfetch_module

Leitura:
```bash
sudo cat /dev/kfetch
```
Exemplo de saída:
```bash

 <(o )___
   ( ._> /
    `---'
NOME-DO-HOST
==============================
Kernel: 6.8.0-51-generic
CPU: Intel(R) Core(TM) i7-XXXX
CPUs: 12
Mem: 7854 / 7854 MB
Uptime: 84 minutos
Proc: 345
```

Modificar máscara (opcional): Você pode definir quais informações deseja visualizar utilizando uma máscara binária.

Exemplo: mostrar apenas Kernel e Memória
```bash
echo 9 | sudo tee /dev/kfetch  # 9 = 0b01001 (KERNEL + MEM)
```

## 📕 risk_module

Ver PIDs ativos:
```bash
ps -eo pid,comm
```

Setar PID a ser avaliado:
```bash
echo 1234 | sudo tee /proc/process_risk/risk_score
```

Ler risco:
```bash
cat /proc/process_risk/risk_score
```

Exemplo de saída:
```c
PID 1234 - Risk: Medium
```

Saída com cores ANSI (verde, amarelo ou vermelho) dependendo do nível de risco.


### Remover os módulos
```bash
sudo rmmod risk_module
sudo rmmod kfetch_module
```


## 💡 Lógica de Risco (risk_module)

    Avalia o tempo total de CPU usado (utime + stime)

    Classifica o risco:

        Baixo: tempo < 50% do threshold

        Médio: entre 50% e 100%

        Alto: acima de 100% (> 100000 jiffies)

## 📌 Observações

    Necessário ter headers do kernel instalados (linux-headers-$(uname -r))

    Requer permissões de root para carregar módulos e acessar /proc ou /dev

    Códigos ANSI de cor são visíveis apenas em terminais compatíveis

## 🛠️ Futuras melhorias

    Incluir análise de /proc/[pid]/io no espaço de usuário (daemon)

    Comunicação via Netlink ou ioctl

    Monitoramento contínuo de processos
