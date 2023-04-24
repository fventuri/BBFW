# Utilities

## extract_startup_params
Extracts parameters (IVT and important memory addresses) from a firmware file based on a startup function (for example: [startup_stm32f427xx.s](https://github.com/STMicroelectronics/STM32CubeF4/tree/master/Drivers/CMSIS/Device/ST/STM32F4xx/Source/Templates/gcc/startup_stm32f427xx.s))

To create a load file for r2:
```
./extract_startup_params.py -r -s ../private/startup_stm32f427xx.s ../X6100_BBFW_V1.1.6_221112001.img > ../radare2/20221112.r2
```

```
./extract_startup_params.py -r -s ../private/startup_stm32f427xx.s ../X6100_BBFW_V1.1.6_221102001.img > ../radare2/20221102.r2
```

```
./extract_startup_params.py -r -s ../private/startup_stm32f427xx.s ../X6100_BBFW_20220410001.img > ../radare2/20220410.r2
```

```
./extract_startup_params.py -r -s ../private/startup_stm32f427xx.s ../X6100_BBFW_20211207001.img > ../radare2/20211207.r2
```
