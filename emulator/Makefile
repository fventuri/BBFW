# Makefile for running BBFW functions on local PC
# based on: https://github.com/travisgoodspeed/md380tools/blob/master/emulator/Makefile
#
# Franco Venturi - Sat Jan 21 09:41:18 PM EST 2023

# Comment/uncomment the next few lines according to your distribution/packages

# Debian/Ubuntu or Fedora using Copr packages from lantw44/arm-linux-gnueabi-toolchain
ARM_GCC = arm-linux-gnueabi-gcc
ARM_OBJCOPY = arm-linux-gnueabi-objcopy

# Fedora using ARM toolchain
#export PATH := /opt/arm-gnu-toolchain/bin:${PATH}
#ARM_GCC = arm-none-linux-gnueabihf-gcc
#ARM_OBJCOPY = arm-none-linux-gnueabihf-objcopy


# version from 2022/11/12
BBFW=../X6100_BBFW_V1.1.6_221112001.img
SYMBOLS_FILE=symbols_20221112
ADDRESSES_FILE=addresses_20221112

# version from 2022/11/02
#BBFW=../X6100_BBFW_V1.1.6_221102001.img
#SYMBOLS_FILE=symbols_20221102
#ADDRESSES_FILE=addresses_20221102

# version from 2022/04/10
#BBFW=../X6100_BBFW_20220410001.img
#SYMBOLS_FILE=symbols_20220410
#ADDRESSES_FILE=addresses_20220410

# version from 2021/12/07
#BBFW=../X6100_BBFW_20211207001.img
#SYMBOLS_FILE=symbols_20211207
#ADDRESSES_FILE=addresses_20211207


CC=$(ARM_GCC) -static -g

PROG=snprintf-emu

-include addressfile

all: $(PROG)

snprintf-emu: snprintf-emu.o firmware.o ram.o
	$(CC) -o $@ $^ \
		$(LDFLAGS) \
		-z noexecstack \
		-Xlinker --just-symbols=$(SYMBOLS_FILE) \
		-Xlinker --section-start=.firmware=$(_BASE) \
		-Xlinker --section-start=.sram=$(_SDATA)

run: $(PROG)
	./$(PROG)

firmware.o: $(BBFW) addressfile
	$(ARM_OBJCOPY) \
		-I binary $< \
		--change-addresses=$(_BASE) \
		--rename-section .data=.firmware \
		-O elf32-littlearm -B arm $@

ram.o: ram.img addressfile
	$(ARM_OBJCOPY) \
		-I binary $< \
		--change-addresses=$(_SDATA) \
		--rename-section .data=.sram \
		-O elf32-littlearm -B arm $@

ram.img: $(BBFW) addressfile
	dd if=$< bs=$$(($$(printf "%d - %d" $(_SIDATA) $(_BASE)))) skip=1 | \
	dd of=$@ bs=$$(($$(printf "%d - %d" $(_EDATA) $(_SDATA)))) count=1
        # zero all the rest of the RAM (just to be on the safe side)
	dd if=/dev/zero of=$@ bs=$$(($$(printf "%d - %d" $(_ESTACK) $(_EDATA)))) count=1 oflag=append conv=notrunc
        # zero just BSS
	#dd if=/dev/zero of=$@ bs=$$(($$(printf "%d - %d" $(_EBSS) $(_SSS)))) count=1 oflag=append conv=notrunc

addressfile: $(ADDRESSES_FILE)
	@awk '!/^#/ { print toupper($$1) "=0x" $$2 }' $< > $@

clean:
	rm -f $(PROG) *.o ram.img addressfile
