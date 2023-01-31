# load the image
f _base = 0x08020000
o ../X6100_BBFW_V1.1.6_221112001.img _base rx
omn _base flash

# IVT functions
fs symbols
f sym.Reset_Handler = 0x08032d84
f sym.DMA1_Stream3_IRQHandler = 0x08023bf0
f sym.TIM2_IRQHandler = 0x08032cb4
f sym.TIM3_IRQHandler = 0x0802c8d4
f sym.TIM4_IRQHandler = 0x08032cec
f sym.I2C3_EV_IRQHandler = 0x08032294
f sym.I2C3_ER_IRQHandler = 0x08032478
f sym.Default_Handler = 0x08032dd4

# useful memory addresses
fs *
f _estack = 0x20030000
f _sdata = 0x20000000
f _edata = 0x20003558
f _sidata = 0x08079ee8
f _sbss = 0x20003558
f _ebss = 0x2000e20c

# more functions from Reset_Handler
fs symbols
f sym.SystemInit = 0x08032bf8
f sym.__libc_init_array = 0x08034e20
f sym.main = 0x08032960

s _base
