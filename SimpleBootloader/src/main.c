#include "stm32f4xx_hal.h"

void appjmp_goto(uint32_t app_addr)	__attribute__((optimize("-O0")));
void appjmp_enable() 	__attribute__((optimize("-O0")));

static uint8_t enabled=0;

// This stuff doesn't appear to be needed, but I'll keep it commented here for now just in case.
// void appjmp_init_vectors()  __attribute__((optimize("-O0")));
// volatile uint32_t g_pfnVectors[];

// static uint32_t vectorTable_RAM[256] __attribute__(( aligned(0x200ul) ));
// void appjmp_init_vectors()
// {
// 	__disable_irq();
// 	memmove(vectorTable_RAM,g_pfnVectors,256*sizeof(uint32_t));
// 	SCB->VTOR = 0x8020000;
// 	__DSB();
// 	__ISB();
// }

void appjmp_goto(uint32_t app_addr)
{
	if(enabled != 1)
	   return;
	__disable_irq();
	for(int i = 0;i < 8;i++) NVIC->ICER[i] = 0xFFFFFFFF;
	for(int i = 0;i < 8;i++) NVIC->ICPR[i] = 0xFFFFFFFF;
	__set_CONTROL(0);
	__set_MSP(*(__IO uint32_t*)app_addr);
	uint32_t JumpAddress = *((volatile uint32_t*) (app_addr + 4));
	__ISB();
	__DSB();
	SysTick->CTRL &= ~(SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk);
	void (*reset_handler)(void) = (void*)JumpAddress;
	while(1)
	   reset_handler();
}

void appjmp_enable()
{
	enabled = 1;
}

int main(void) {
  // set the vector table offset
  SCB->VTOR = 0x8000000;

  // wait for all memory accesses to complete
	__DSB();

  // throw out any prefetched instructions
	__ISB();

  // Initialize the HAL
  HAL_Init();

  // enable appjmp. This is to do some other stuff if we ever need to
  // probably move most of the above stuff in here, but this works for now.
  appjmp_enable();

  // jump to the application start address
  appjmp_goto(0x8020000); 
  
  return 0;
}







// various interrupt handlers
void SysTick_Handler(void)
{
  HAL_IncTick();
}

void NMI_Handler(void)
{
}

void HardFault_Handler(void)
{
  while (1) {}
}


void MemManage_Handler(void)
{
  while (1) {}
}

void BusFault_Handler(void)
{
  while (1) {}
}

void UsageFault_Handler(void)
{
  while (1) {}
}

void SVC_Handler(void)
{
}

void DebugMon_Handler(void)
{
}

void PendSV_Handler(void)
{
}