# Makefile para compilar múltiplos módulos do kernel

# Definir os módulos que queremos compilar
obj-m += risk_module.o     # Módulo de risco
obj-m += kfetch_module.o   # Módulo kfetch

# Regra padrão para compilar os módulos
all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Regra para limpar arquivos de compilação
clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#Como Usar o Makefile:
#Compilar os módulos:
#No diretório onde os arquivos risk_module.c, kfetch_module.c e o Makefile estão localizados, execute o seguinte comando:

#bash
#Copiar código
#make
#Isso vai gerar os módulos risk_module.ko e kfetch_module.ko.

#Limpar os arquivos de compilação:
#Para limpar os arquivos gerados durante a compilação, execute:

#bash
#Copiar código
#make clean