obj-m := kfetch_module.o risk_module.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

#make clean && make
#sudo insmod kfetch_module.ko
#sudo insmod risk_module.ko
#ls /dev/kfetch
#cat /dev/kfetch (se permissao negada inserir sudo no inicio)
#cat /proc/process_risk/risk_score

#
#
#sudo rmmod risk_module
#make clean && make
#sudo insmod risk_module.ko
#ls -l /proc/process_risk
#
#PAra escolher qual pid do porcesso que quer avaiar
# ps -eo pid,comm

#echo 1234 | sudo tee /proc/process_risk/risk_score
#cat /proc/process_risk/risk_score

#sudo rmmod risk_module
#sudo rmmod kfetch_module
