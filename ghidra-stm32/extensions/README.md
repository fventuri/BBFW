# Ghidra SMT32 - Ghidra extensions for the STM32 platform

STM32Loader is a Ghidra loader that allows to load STM32F4 binary firmware files and creates the basic memory structure including the peripherals memory mappings. [**It depends on a Ghidra GDT archive file created with the script 'CreateSTM32GDTArchive'**](https://github.com/0x6E75/BBFW/tree/main/ghidra-stm32/scripts)

## How to build, install, and use STM32Loader

### Building STM32Loader

This step requires openjdk (1.19.0), Ghidra (10.3+), and the build tool 'gradle' (8.1.1). The loader might only work with your version of Ghidra.

```bash
GDIR=$(find /*/ghidra*/ghidraRun | grep -P -o "(.*)(?=/ghidraRun)")
export GHIDRA_INSTALL_DIR="${GDIR}" # set this to your ghidra installation directory

sudo apt-get install openjdk-19-jdk # install JDK 19 and set it to default jdk
	sudo update-java-alternatives --jre-headless -s java-1.19*

cd ~/Downloads # install gradle 8.1.1
	wget https://downloads.gradle.org/distributions/gradle-8.1.1-all.zip
	7z x gradle-8.1.1-all.zip
	sudo mv gradle-8.1.1/ /opt/.
	echo 'export PATH=/opt/gradle-8.1.1/bin:$PATH' | sudo tee -a ~/.bashrc
	export PATH=/opt/gradle-8.1.1/bin:$PATH

sudo apt-get install git
	git clone https://github.com/fventuri/BBFW.git # compile our ghidra loader
	cd BBFW/ghidra-stm32/extensions/STM32Loader
		gradle
	 	sudo mv dist/ghidra_*_STM32Loader.zip $GHIDRA_INSTALL_DIR/.
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
- Select the STM32 _non-encyrpted_ gcore binary firmware file to load.
- **Change the 'Format' option from 'Raw Binary' to 'STM32 Loader (Standard Peripheral Library)**
- Parameters to load the gcore firmware file should auto-fill: Architecture (ex: ARM:LE:32:Cortex:default) and 'Options...' submenu values such as path for the STM32 GDT archive file and the base address where the program should be loaded (0x08020000 in our case) should be populated by the loader but please double-check them.
- Click 'OK' and the STM32 binary firmware file will be loaded into Ghidra
- Finally double click on the file just loaded in the Project Manager tool to start the CodeBrowser and run the initial full analysis of the image
