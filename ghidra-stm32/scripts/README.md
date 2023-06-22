# Ghidra SMT32 scripts - Ghidra scripts for the STM32 platform

- CreateSTM32GDTArchive is a headless script that creates a Ghidra Data Type (GDT) archive from the STM32F4 Standard Peripherals Library [STSW-STM32065](https://www.st.com/en/embedded-software/stsw-stm32065.html)

## How to run CreateSTM32GDTArchive

The script CreateSTM32GDTArchive requires a few configuration settings (like the path of the STM32 Standard Peripheral Library installation), that can provided either via its properties file or via command line parameters.

- To run it using the settings from the properties file:
```
$GHIDRA_HOME/support/analyzeHeadless /tmp tempproj -preScript CreateSTM32GDTArchive.py -deleteProject
```

- To run it passing the settings from the command line:
```
$GHIDRA_HOME/support/analyzeHeadless /tmp tempproj -preScript CreateSTM32GDTArchive.py spl_install_dir=/opt/STM32F4xx_DSP_StdPeriph_Lib_V1.9.0 mcu_variant=STM32F427_437xx output_dir=/tmp -deleteProject
```
- Here is an example:
```bash
GHIDRA_HOME=/opt/ghidra_10.3.1_PUBLIC # set this to your ghidra installation directory

cd ~/Downloads # download standard peripheral library
	wget https://web.archive.org/web/20230622050333/https://www.st.com/content/ccc/resource/technical/software/firmware/group1/42/1a/98/f3/14/b4/4b/81/stsw-stm32065_v1-9-0/files/stsw-stm32065_v1-9-0.zip/jcr:content/translations/en.stsw-stm32065_v1-9-0.zip
	sudo 7z x en.stsw-stm32065_v1-9-0.zip -o"/opt/"

git clone https://github.com/fventuri/BBFW.git # create the .gdt file
	cd BBFW/ghidra-stm32/scripts/
	sudo $GHIDRA_HOME/support/analyzeHeadless /tmp tempproj -preScript CreateSTM32GDTArchive.py output_dir=/opt -deleteProject
```

The sctipt will create a GDT file called <mcu_variant>.gdt in the 'output_dir' directory.
