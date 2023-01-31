# load the image
f _base = 0x08020000
o ../X6100_BBFW_20211207001.img _base rx
omn _base flash

# IVT functions
fs symbols
f sym.Reset_Handler = 0x08030a2c
f sym.DMA1_Stream3_IRQHandler = 0x08023628
f sym.TIM2_IRQHandler = 0x0803095c
f sym.TIM3_IRQHandler = 0x0802b748
f sym.TIM4_IRQHandler = 0x08030994
f sym.I2C3_EV_IRQHandler = 0x08030054
f sym.I2C3_ER_IRQHandler = 0x080301b8
f sym.Default_Handler = 0x08030a7c

# useful memory addresses
fs *
f _estack = 0x20030000
f _sdata = 0x20000000
f _edata = 0x2000c194
f _sidata = 0x080773e0
f _sbss = 0x2000c194
f _ebss = 0x2000d8e4

# more functions from Reset_Handler
fs symbols
f sym.SystemInit = 0x0803089c
f sym.__libc_init_array = 0x08032c08
f sym.main = 0x080305f0

s _base
