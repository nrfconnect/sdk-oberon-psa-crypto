#define __NVIC_PRIO_BITS          4 /*!< M4 uses 4 Bits for the Priority Levels    */

typedef enum IRQn
{
/******  Cortex-M4 Processor Exceptions Numbers ***************************************/
    NonMaskableInt_IRQn           = -14,      /*!<  2 Non Maskable Interrupt          */
    HardFault_IRQn                = -13,      /*!<  3 HardFault Interrupt             */
    MemoryManagement_IRQn         = -12,      /*!<  4 Memory Management Interrupt     */
    BusFault_IRQn                 = -11,      /*!<  5 Bus Fault Interrupt             */
    UsageFault_IRQn               = -10,      /*!<  6 Usage Fault Interrupt           */
    SVCall_IRQn                   =  -5,      /*!< 11 SV Call Interrupt               */
    DebugMonitor_IRQn             =  -4,      /*!< 12 Debug Monitor Interrupt         */
    PendSV_IRQn                   =  -2,      /*!< 14 Pend SV Interrupt               */
    SysTick_IRQn                  =  -1,      /*!< 15 System Tick Interrupt           */
} IRQn_Type;


#include <stdio.h>
#include <rt_misc.h>
#include <core_cm4.h>

//#pragma import(__use_no_semihosting_swi)


volatile int ITM_RxBuffer = ITM_RXBUFFER_EMPTY;  /*  CMSIS Debug Input        */


//struct __FILE { int handle; /* Add whatever you need here */ };
//FILE __stdout;
//FILE __stdin;
//FILE __stderr;


int fputc(int c, FILE *f) {
    if (c == '\n')  {
        ITM_SendChar('\r');
    }
    return (int)ITM_SendChar((uint32_t)c);
}


//int fgetc(FILE *f) {
//    while (ITM_CheckChar() != 1) __NOP();
//    return (ITM_ReceiveChar());
//}


//int fclose(FILE* f) {
//    return (0);
//}


//int fseek (FILE *f, long nPos, int nMode)  {
//    return (0);
//}


//int fflush (FILE *f)  {
//    return (0);
//}

int ferror(FILE *f) {
    /* Your implementation of ferror */
    return (EOF);
}


void _ttywrch(int c) {
    ITM_SendChar(c);
}


void _sys_exit(int return_code) {
    __asm("bkpt 0"); // stop debugger
    for (;;);        // endless loop
}


/*********** Cpu Cycles **********/

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

// Interrupt handler, called automatically on
// TIMER1 overflow
void SysTick_Handler()
{
    ticks += 0x01000000 - 32; // 32 cycles interrupt handler overhead
}

uint64_t cpucycles(void)
{
    if(!init) cpucycles_init();
    return ticks - (unsigned long)SysTick->VAL;
}
