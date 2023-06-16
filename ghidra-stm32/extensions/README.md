# Ghidra SMT32 - Ghidra extensions for the STM32 platform

STM32Loader is a Ghidra loader that allows to load STM32F4 binary firmware files and creates the basic memory structure including the peripherals memory mappings. It depends on a Ghidra GDT archive file created with the script 'CreateSTM32GDTArchive'

## How to build, install, and use STM32Loader

### Building STM32Loader

This step requires the build tool 'gradle'.

```
cd STM32Loader
gradle
```

If the gradle command is successful, there should be an installation file in the 'dist' directory called something like ghidra_<ghidra_version>_<YYYYMMDD>_STM32Loader.zip

### Installing STM32Loader for the first time

In the Ghidra Project Manager tool (which is the first Ghidra window to be created when Ghidra is launched), choose 'File -> Install Extensions...'

### Quick way to install STM32Loader after the first time

After making changes and rebuilding STM32Loader, it can be reinstalled on top of the previous installation by simply unzipping the install zip file into the directory '$HOME/.ghidra/.ghidra_<ghidra_version>/Extensions'. For instance for Ghidra version 10.3_PUBLIC the unzip command would be:
```
unzip -q -o -d ~/.ghidra/.ghidra_10.3_PUBLIC/Extensions dist/ghidra_10.3_PUBLIC_$(date +%Y%m%d)_STM32Loader.zip
```

### Using SMT32Loader to load an STM32F4 binary firmware file

- Make sure you have the STM32F4 Ghidra Data Types archive file built with the 'CreateSTM32GDTArchive' script
- Select the menu item 'Import File...' either in the Project Manger tool or in the CodeBrowser tool
- Select the STM32 binary firmware file to load, and change the 'Format' option from 'Raw Binary' to 'STM32 Loader (Standard Peripheral Library); you can use the 'Options...' submenu to change the path for the STM32 GDT archive file or the base address where the program should be loaded
- Click 'OK' and the STM32 binary firmware file will be loaded into Ghidra
- Finally double click on the file just loaded in the Project Manager tool to start the CodeBrowser and run the initial full analysis of the image
