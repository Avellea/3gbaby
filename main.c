#include "nskbl.h"

typedef struct _ScePsCode
{
    uint16_t company_code;
    uint16_t product_code;
    uint16_t product_sub_code;
    uint16_t factory_code;
} ScePsCode;

void _start() __attribute__((weak, alias("module_start")));
int module_start(int argc, void *args)
{
    SceKblParam *pSysrootKbl = ((SceSysroot *)sceKernelSysrootGetSysroot())->pKblParam;
    if (pSysrootKbl->magic == 0xCBAC03AA)
    {
        memset(&pSysrootKbl->QAF, 0xFF, 0x10);

        pSysrootKbl->hardwareInfo |= 0x02; // Enable 3G Flag
        printf("[3G Baby                  ] Set to 3G.\n");
    }

    return 1;
}

void _stop() __attribute__((weak, alias("module_stop")));
int module_stop(void) { return 0; }