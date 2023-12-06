obj-m:=main.o
miscregester:
	make -C /lib/modules/5.19.0-35-generic/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/5.19.0-35-generic/build M=$(shell pwd) clean