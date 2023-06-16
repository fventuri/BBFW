# Ghidra SMT32 - Ghidra scripts and extensions for the STM32 platform

This directory contains some useful Ghidra scripts and extentions specifically for the STM32 platform.

## Scripts

- CreateSTM32GDTArchive is a headless script that creates a Ghidra Data Type (GDT) archive from the STM32F4 Standard Peripherals Library [STSW-STM32065](https://www.st.com/en/embedded-software/stsw-stm32065.html)


## Extensions

- STM32Loader is a Ghidra loader that allows to load STM32F4 binary firmware files and creates the basic memory structure including the peripherals memory mappings. It depends on a Ghidra GDT archive file created with the script 'CreateSTM32GDTArchive'
