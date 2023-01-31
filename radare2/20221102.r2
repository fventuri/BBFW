# load the image
f _base = 0x08020000
o ../X6100_BBFW_V1.1.6_221102001.img _base rx
omn _base flash

# IVT functions
fs symbols
f sym.Reset_Handler = 0x08032bd4
f sym.DMA1_Stream3_IRQHandler = 0x08023bf0
f sym.TIM2_IRQHandler = 0x08032b04
f sym.TIM3_IRQHandler = 0x0802c7e8
f sym.TIM4_IRQHandler = 0x08032b3c
f sym.I2C3_EV_IRQHandler = 0x080320e4
f sym.I2C3_ER_IRQHandler = 0x080322c8
f sym.Default_Handler = 0x08032c24

# useful memory addresses
fs *
f _estack = 0x20030000
f _sdata = 0x20000000
f _edata = 0x2000354c
f _sidata = 0x08079c90
f _sbss = 0x2000354c
f _ebss = 0x2000e200

# more functions from Reset_Handler
fs symbols
f sym.SystemInit = 0x08032a48
f sym.__libc_init_array = 0x08034c70
f sym.main = 0x080327b0

s _base
