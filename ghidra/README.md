## Getting started reversing the X6100 BBFW in Ghidra
New users can try running [gettingstarted.sh](gettingstarted.sh) to install Ghidra, decrypt the BBFW.xgf, and import known data types (.gdt) & symbols that we have discovered so far.

## Importing/running community Ghidra scripts
 1. Download the ghidra scripts you want to use (they should be .java or .py files). Some useful scripts for reversing STM32 firmware include [symgrate](https://github.com/jamchamb/symgrate-ghidra) (to match function signatures) & [SVD Loader](https://github.com/leveldown-security/SVD-Loader-Ghidra) (to create the STM32's memory map in Ghidra).
 2. Go to Ghidra > Code Browser (dragon button) > "Window" (tab) > "Script Manager" (green circle 'play' button) > "Manage Script Directories" (three horizontal lines button) > "Display file chooser to add bundles to list" (green plus button).
 3. Now find/select the directory holding your ghidra script, press "OK", then close the window.
 4. Search for your script in the left or main windows under "Filter:" (for example, to find Ghidra's built-in address/function exporter script, type "export"). Select your script by clicking on it, then click "Run Script" (green 'play' button).

## Creating Ghidra Data Type files from C source on Linux
 - [Ghidra: Data Type Manager / Archives and Parse C Source... (resolve function signatures)](https://www.youtube.com/watch?v=u15-r5Erfnw) (mich/0x6d696368, 04/2019) _Importing data types into Ghidra from sourcecode header files_
 1. Find a sourcecode header file that you believe could contain functions included in your firmware (for example: [stm32f427xx.h](https://github.com/STMicroelectronics/STM32CubeF4/blob/master/Drivers/CMSIS/Device/ST/STM32F4xx/Include/stm32f427xx.h).  If there are other 'include' directories in this file's repo then just clone the whole repo (in case your header file depends on any other files in the repo). 
 2. Go to Ghidra > Code Browser (dragon button) > "File" (tab) > "Parse C Source..." > "Save profile to new name" (small floppy disk button) > Enter a name for your new Parse C Source profile (mine was 'stm32f427xx').  Now add your .h file and try to "Parse to File..."
 3. If everything went well, you should now have a .gdt file that you can import into the Ghidra Code Browser "Data Type Manager" window (bottom-left).  But Ghidra sucks at parsing C files, so it will probably crash.
 4. If Ghidra's Parse C Source tool does crash, then we will probably need some help from a github script called "[Gdt helper](https://github.com/kohnakagawa/gdt_helper)": Delete everything in the upper and lower areas of your Parse C Source profile (shift-click to select everything and then delete it).  Then open a Linux terminal window, enter these commands, then follow the directions that gdt_helper prints to the terminal (in gold text) to set up Ghidra's Parse C Source tool to work with your computer:

```bash
sudo apt-get install glibc-source git clang #you might also need python3, gcc doesn't work for me but clang does
cd ~/Downloads
git clone https://github.com/STMicroelectronics/STM32CubeF4.git

curl -sSL https://install.python-poetry.org | python3 -
git clone https://github.com/kohnakagawa/gdt_helper.git
cd gdt_helper
poetry shell
poetry update
poetry install
python gdt_helper.py make-parse-options clang

#This will output a ton of stuff.
#Follow the instructions in gold text: Copy all the stuff from the terminal and then paste it into the 'Parse C Source' options window in Ghidra.

#Then form a command like this (based on instructions from https://github.com/kohnakagawa/gdt_helper#how-to-use):
python gdt_helper.py make-file-to-parse clang ~/Downloads/STM32CubeF4/Drivers/CMSIS/Device/ST/STM32F4xx/Include/stm32f427xx.h --additional-includes ~/Downloads/STM32CubeF4/Drivers/CMSIS/Core/Include
#Follow the instructions in the terminal to finish setting up the 'Parse C Source' options window in Ghidra.
```
 5. You should now be able to make a .gdt file with the structs from the .h file.
 6. Now try importing your .gdt file into the Ghidra Code Browser "Data Type Manager" window (bottom-left window, black down arrow button).
