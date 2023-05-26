PLUGIN_OBJS = main.o
HEADERS = $(wildcard *.h)

PREFIX  = arm-vita-eabi
CC      = $(PREFIX)-gcc
CFLAGS  = -Wl,-q -Wall -O3 -fPIC -fPIE -I$(VITASDK)/arm-vita-eabi/include
ASFLAGS = $(CFLAGS)

all: 3gbaby.skprx

%.skprx: %.velf
	vita-make-fself -c $< $@

%.velf: %.elf
	vita-elf-create -n -e config.yml $< $@

%.elf: $(PLUGIN_OBJS)
	$(CC) $(CFLAGS) $^ $(PLUGIN_LIBS) -o $@ -nostdlib

clean:
	rm 3gbaby.skprx