# load the image
f _base = 0x08020000
o ../X6100_BBFW_20220410001.img _base rx
omn _base flash

# IVT functions
fs symbols
f sym.Reset_Handler = 0x08031e34
f sym.DMA1_Stream3_IRQHandler = 0x08023838
f sym.TIM2_IRQHandler = 0x08031d64
f sym.TIM3_IRQHandler = 0x0802bbf4
f sym.TIM4_IRQHandler = 0x08031d9c
f sym.I2C3_EV_IRQHandler = 0x08031354
f sym.I2C3_ER_IRQHandler = 0x08031538
f sym.Default_Handler = 0x08031e84

# useful memory addresses
fs *
f _estack = 0x20030000
f _sdata = 0x20000000
f _edata = 0x2000353c
f _sidata = 0x08079020
f _sbss = 0x2000353c
f _ebss = 0x2001124c

# more functions from Reset_Handler
fs symbols
f sym.SystemInit = 0x08031ca4
f sym.__libc_init_array = 0x08034010
f sym.main = 0x08031a20

s _base
