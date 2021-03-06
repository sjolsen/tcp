DEBUG=-gdwarf-2 -O0 -z execstack

all: tcpc tcps tcph attack attack2
	@echo done

tcpc: tcpc.c
	gcc -Wall $(DEBUG) -o tcpc tcpc.c

tcps: tcps.c
	gcc -Wall $(DEBUG) -o tcps tcps.c

tcph: tcph.c
	gcc -Wall $(DEBUG) -o tcph tcph.c

attack: attack.c
	gcc -Wall $(DEBUG) -o attack attack.c

attack2: attack2.c
	gcc -std=c99 -Wall $(DEBUG) -o attack2 attack2.c

clean:
	rm -f tcpc tcps tcph attack attack2 bad.dat

install: all
	@su -c "./install.sh"
