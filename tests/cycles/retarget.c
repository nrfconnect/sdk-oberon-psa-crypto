#include "test_cycles.h"


void _sys_init(void)
{
}

void _sys_exit(int return_code)
{
    (void)return_code;
}


/*********** Cpu Cycles **********/

uint64_t cpucycles(void)
{
    return 0; // replace code with platform specific cycle count
}


/******** Example Cortex-M *******

#define CYCLES_INTERRUPT_HANDLER_OVERHEAD_M0 32
#define CYCLES_INTERRUPT_HANDLER_OVERHEAD_M4 40

static unsigned char init = 0;
static volatile uint64_t ticks;

static void cpucycles_init(void)
{
    SysTick->LOAD = 0x00FFFFFF;
    SysTick->VAL = 0;
    SysTick->CTRL |= SysTick_CTRL_ENABLE_Msk | SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_CLKSOURCE_Msk;
    ticks = 0x01000000;
    init = 1;
}

// Interrupt handler, called automatically on TIMER1 overflow
void SysTick_Handler()
{
    ticks += 0x01000000 - CYCLES_INTERRUPT_HANDLER_OVERHEAD_M0;
}

uint64_t cpucycles(void)
{
    if(!init) cpucycles_init();
    return ticks - (unsigned long)SysTick->VAL;
}
*/