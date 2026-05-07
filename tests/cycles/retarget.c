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
