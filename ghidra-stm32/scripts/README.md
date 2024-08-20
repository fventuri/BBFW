# Ghidra SMT32 scripts - Ghidra scripts for the STM32 platform

## CreateSTM32GDTArchive

CreateSTM32GDTArchive is a headless script that creates a Ghidra Data Type (GDT) archive from the STM32F4 Standard Peripherals Library [STSW-STM32065](https://www.st.com/en/embedded-software/stsw-stm32065.html)

### How to run CreateSTM32GDTArchive

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
GHIDRA_HOME=$(find /*/ghidra*/ghidraRun | grep -P -o "(.*)(?=/ghidraRun)") #GHIDRA_HOME=/opt/ghidra_10.3.3_PUBLIC - (set this to your ghidra installation directory)

cd ~/Downloads # download standard peripheral library
	wget https://web.archive.org/web/20230622050333/https://www.st.com/content/ccc/resource/technical/software/firmware/group1/42/1a/98/f3/14/b4/4b/81/stsw-stm32065_v1-9-0/files/stsw-stm32065_v1-9-0.zip/jcr:content/translations/en.stsw-stm32065_v1-9-0.zip
	sudo 7z x en.stsw-stm32065_v1-9-0.zip -o"/opt/"

git clone https://github.com/fventuri/BBFW.git # create the .gdt file
	cd BBFW/ghidra-stm32/scripts/
	sudo $GHIDRA_HOME/support/analyzeHeadless /tmp tempproj -preScript CreateSTM32GDTArchive.py output_dir=$GHIDRA_HOME -deleteProject
```

The script will create a GDT file called <mcu_variant>.gdt in the 'output_dir' directory.

---
If the script encounters an error with `fatal error: stdint.h: No such file or directory`, you can work around this error by creating `.../STM32F4xx_DSP_StdPeriph_Lib_V1.9.0/Libraries/STM32F4xx_StdPeriph_Driver/inc/stdint.h` with these file contents:
```C
/* minumum needed to parse STM32F4 Standard Peripheral Library headers
 * Franco Venturi - Tue Feb 21 10:14:54 PM EST 2023
 */

/* fundamental types */
typedef long unsigned int uint32_t;
typedef long int int32_t;
typedef unsigned char uint8_t;
typedef short unsigned int uint16_t;
typedef long long unsigned int uint64_t;
typedef short int int16_t;
typedef signed char int8_t;

/* aliases */
typedef int16_t s16;
typedef int8_t s8;

/* other useful defines */
#define __STATIC_INLINE static inline
```

## AssignFunctionNamesAndTypes

AssignFunctionNamesAndTypes is a headless script that analyzes an STM32 binary and assigns function and names based on a template csv file ('functions.csv'). It uses address and a combination of functionId (i.e. full hash and specific hash) or reference functions plus offsets (and specific hash matching) for smaller functions for which a functionId is not available.

### Arguments

- `gdt_archives`: comma separated list of GDT archives that contain the typedef's of the identified functions
- `functions`: name of the CSV file containing the function identification information and other function useful information
- `output_functions`: flag to indicate if an output functions file should be created; this file contains all the correct information (hashes and reference functions) for a specific firmware file; it can be used as the starting point to create another functions CSV file for a different release of the same firmware
- `append_suffix`: flag to indicate if the suffix should be appended to the function name (for instance instead of `Reset_Handler`, the name would be `Reset_handler_f`)

### How to run AssignFunctionNamesAndTypes

The script AssignFunctionNamesAndTypes requires a few configuration settings (like the path of the template CSV file describing functions of the flag to indicate if the suffix should be appended to the function name), that can provided either via its properties file or via command line parameters.

- To run it passing the settings from the command line:
```
$GHIDRA_HOME/support/analyzeHeadless /tmp bbfw-20221112 -import X6100_BBFW_V1.1.6_221112001.bin -loader STM32Loader -postScript AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=functions.csv output_functions
```

#### Other examples:
```
$GHIDRA_HOME/support/analyzeHeadless . 20211207001 -import X6100_BBFW_20211207001.bin -loader STM32Loader -postScript AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=functions.csv
```

```
$GHIDRA_HOME/support/analyzeHeadless . 20220410001 -import X6100_BBFW_20220410001.bin -loader STM32Loader -postScript AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=functions.csv
```

```
$GHIDRA_HOME/support/analyzeHeadless . 20221102001 -import X6100_BBFW_V1.1.6_221102001.bin -loader STM32Loader -postScript AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=functions.csv
```

```
$GHIDRA_HOME/support/analyzeHeadless . 20221112001 -import X6100_BBFW_V1.1.6_221112001.bin -loader STM32Loader -postScript AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=functions.csv
```

