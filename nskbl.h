/* nskbl.h -- imported data from non-secure bootloader
 *
 * Copyright (C) 2017 molecule, 2018-2022 skgleba, 2022 CreepNT
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#ifndef NSKBL_HEADER
#define NSKBL_HEADER

#define NSKBL_FIRMWARE_VERSION 0x36500000U

#include <stddef.h>
#include <stdint.h>
#include <psp2common/types.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#define DACR_OFF(stmt)                 \
do {                                   \
    unsigned prev_dacr;                \
    __asm__ volatile(                  \
        "mrc p15, 0, %0, c3, c0, 0 \n" \
        : "=r" (prev_dacr)             \
    );                                 \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (0xFFFF0000)           \
    );                                 \
    stmt;                              \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (prev_dacr)            \
    );                                 \
} while (0)

typedef struct SceModuleExports {
  uint16_t size;           // size of this structure; 0x20 for Vita 1.x
  uint8_t  lib_version[2]; //
  uint16_t attribute;      // ?
  uint16_t num_functions;  // number of exported functions
  uint16_t num_vars;       // number of exported variables
  uint16_t unk;
  uint32_t num_tls_vars;   // number of exported TLS variables?  <-- pretty sure wrong // yifanlu
  uint32_t lib_nid;        // NID of this specific export list; one PRX can export several names
  char     *lib_name;      // name of the export module
  uint32_t *nid_table;     // array of 32-bit NIDs for the exports, first functions then vars
  void     **entry_table;  // array of pointers to exported functions and then variables
} __attribute__((packed)) SceModuleExports;

#define EI_NIDENT 16
typedef struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT]; /* ident bytes */
  uint16_t  e_type;     /* file type */
  uint16_t  e_machine;    /* target machine */
  uint32_t  e_version;    /* file version */
  uint32_t  e_entry;    /* start address */
  uint32_t e_phoff;    /* phdr file offset */
  uint32_t e_shoff;    /* shdr file offset */
  uint32_t  e_flags;    /* file flags */
  uint16_t  e_ehsize;   /* sizeof ehdr */
  uint16_t  e_phentsize;    /* sizeof phdr */
  uint16_t  e_phnum;    /* number phdrs */
  uint16_t  e_shentsize;    /* sizeof shdr */
  uint16_t  e_shnum;    /* number shdrs */
  uint16_t  e_shstrndx;   /* shdr string index */
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
  uint32_t  p_type;   /* entry type */
  uint32_t p_offset; /* file offset */
  uint32_t  p_vaddr;  /* virtual address */
  uint32_t  p_paddr;  /* physical address */
  uint32_t  p_filesz; /* file size */
  uint32_t  p_memsz;  /* memory size */
  uint32_t  p_flags;  /* entry flags */
  uint32_t  p_align;  /* memory/file alignment */
} __attribute__((packed)) Elf32_Phdr;

typedef struct SceModuleSelfSectionInfo {
  uint64_t offset;
  uint64_t size;
  uint32_t compressed; // 2=compressed
  uint32_t unknown1;
  uint32_t encrypted; // 1=encrypted
  uint32_t unknown2;
} __attribute__((packed)) SceModuleSelfSectionInfo;

typedef struct SceKblParam {
    uint16_t version;
    uint16_t size;
    uint32_t curFw;
    uint32_t minFw;
    uint32_t unkC;
    uint32_t unk10;
    uint32_t unk14[3];
    uint8_t QAF[0x10];
    uint8_t bootFlags[0x10];
    uint8_t dipsw[0x20];
    uintptr_t dramPBase;
    uint32_t dramPSize;
    uint32_t unk68;
    uint32_t bootTypeIndicator1;
    uint8_t OpenPSID[0x10];
    uintptr_t secure_kernel_enp_paddr;
    uint32_t secure_kernel_enp_size;
    uintptr_t context_auth_sm_self_paddr;
    uint32_t context_auth_sm_self_size;
    uintptr_t kprx_auth_sm_pbase;
    uint32_t kprx_auth_sm_size;
    uintptr_t prog_rvk_srvk_paddr;
    uint32_t prog_rvk_srvk_size;
    uint8_t PsCode[0x8];
    uint32_t __stack_chk_guard;
    uint32_t unkAC;
    uint8_t SessionID[0x10];
    uint32_t sleepFactor;
    uint32_t wakeupFactor;
    uint32_t unkC8;
    uint32_t bootControlsInfo;
    uintptr_t suspendinfo_adr;
    uint32_t hardwareInfo;
    uint32_t powerInfo;
    uint32_t unkDC;
    uint32_t unkE0;
    uint32_t unkE4;
    uint8_t hardwareFlags[0x10];
    uint32_t SBLRevision;
    uint32_t magic;
} __attribute__((packed)) SceKblParam;

// firmware specific internal structures

typedef struct _SceSysroot {
    void* pUserdata;
    void* pClass;
    SceSize size;
    SceUInt32 magic1;
    SceUInt32 LOCK;
    SceSize sysrootMappingSize;
    void* vheap;
    SceUInt32 unk1C;
    void* tpidrprw_block;
    SceUInt32 unk24;
    SceUInt32 status;
    uint8_t CORELOCK[8];
    SceUInt32 modulePrivate[14];
    SceKblParam* pKblParam;
    void* pBoot;
    SceUInt32 soc_info;
    SceUInt32 pervmisc_0x4;
    SceUInt32 kermitRevision;
    SceUInt32 hwModel;
    SceUInt32 unk84;
    void* uart8;
    SceUInt32 unk8C;
    SceUInt32 unk90;
    uint8_t unk94[576];
    SceUInt32 unk2DA;
    SceUInt32 unk2D8;
    SceUInt32* unk2DC;
    void* pUIDHeap;
    char* some_names[9];
    struct _SceSysroot* pSysroot;
    void* pUIDSysrootClass;
    SceUInt32 unk310;
    SceUInt32 unk314;
    void* VbaseResetVector;
    SceUInt32 unk31C;
    //....
    uint8_t unk320[0x414 - 0x31C];
    SceUInt32 magic2;
} __attribute__((packed)) SceSysroot;

_Static_assert(sizeof(SceSysroot) == 0x41C, "Bad Sysroot size");


typedef struct SceBootArgs {
  uint16_t version;
  uint16_t size;
  uint32_t fw_version;
  uint32_t ship_version;
  uint32_t field_C;
  uint32_t field_10;
  uint32_t field_14;
  uint32_t field_18;
  uint32_t field_1C;
  uint32_t field_20;
  uint32_t field_24;
  uint32_t field_28;
  uint8_t debug_flags[8];
  uint32_t field_34;
  uint32_t field_38;
  uint32_t field_3C;
  uint32_t field_40;
  uint32_t field_44;
  uint32_t field_48;
  uint32_t aslr_seed;
  uint32_t field_50;
  uint32_t field_54;
  uint32_t field_58;
  uint32_t field_5C;
  uint32_t dram_base;
  uint32_t dram_size;
  uint32_t field_68;
  uint32_t boot_type_indicator_1;
  uint8_t serial[0x10];
  uint32_t secure_kernel_enp_addr;
  uint32_t secure_kernel_enp_size;
  uint32_t field_88;
  uint32_t field_8C;
  uint32_t kprx_auth_sm_self_addr;
  uint32_t kprx_auth_sm_self_size;
  uint32_t prog_rvk_srvk_addr;
  uint32_t prog_rvk_srvk_size;
  uint16_t model;
  uint16_t device_type;
  uint16_t device_config;
  uint16_t retail_type;
  uint32_t field_A8;
  uint32_t field_AC;
  uint8_t session_id[0x10];
  uint32_t field_C0;
  uint32_t boot_type_indicator_2;
  uint32_t field_C8;
  uint32_t field_CC;
  uint32_t resume_context_addr;
  uint32_t field_D4;
  uint32_t field_D8;
  uint32_t field_DC;
  uint32_t field_E0;
  uint32_t field_E4;
  uint32_t field_E8;
  uint32_t field_EC;
  uint32_t field_F0;
  uint32_t field_F4;
  uint32_t bootldr_revision;
  uint32_t magic;
  uint8_t session_key[0x20];
  uint8_t unused[0xE0];
} __attribute__((packed)) SceBootArgs;

typedef struct SceSysrootContext {
  uint32_t reserved[27];
  SceBootArgs *boot_args;
} __attribute__((packed)) SceSysrootContext;

typedef struct SceModuleLoadList {
  const char *filename;
} __attribute__((packed)) SceModuleLoadList;

typedef struct SceObject {
  uint32_t field_0;
  void *obj_data;
  char data[];
} __attribute__((packed)) SceObject;

typedef struct SceModuleSegment {
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint16_t p_flags;
  uint16_t p_align_bits;
  void *buf;
  int32_t buf_blkid;
} __attribute__((packed)) SceModuleSegment;

typedef struct SceModuleObject {
  struct SceModuleObject *next;
  uint16_t exeflags;
  uint8_t status;
  uint8_t field_7;
  uint32_t min_sysver;
  int32_t modid;
  int32_t user_modid;
  int32_t pid;
  uint16_t modattribute;
  uint16_t modversion;
  uint32_t modid_name;
  SceModuleExports *ent_top_user;
  SceModuleExports *ent_end_user;
  uint32_t stub_start_user;
  uint32_t stub_end_user;
  uint32_t module_nid;
  uint32_t modinfo_field_38;
  uint32_t modinfo_field_3C;
  uint32_t modinfo_field_40;
  uint32_t exidx_start_user;
  uint32_t exidx_end_user;
  uint32_t extab_start_user;
  uint32_t extab_end_user;
  uint16_t num_export_libs;
  uint16_t num_import_libs;
  uint32_t field_54;
  uint32_t field_58;
  uint32_t field_5C;
  uint32_t field_60;
  void *imports;
  const char *path;
  uint32_t total_loadable;
  struct SceModuleSegment segments[3];
  void *type_6FFFFF00_buf;
  uint32_t type_6FFFFF00_bufsz;
  void *module_start;
  void *module_init;
  void *module_stop;
  uint32_t field_C0;
  uint32_t field_C4;
  uint32_t field_C8;
  uint32_t field_CC;
  uint32_t field_D0;
  struct SceObject *prev_loaded;
} __attribute__((packed)) SceModuleObject;

typedef struct SceKernelAllocMemBlockKernelOpt {
  uint32_t size;
  uint32_t field_4;
  uint32_t attr;
  uint32_t vbase;
  uint32_t pbase;
  uint32_t alignment;
  uint32_t extraLow;
  uint32_t extraHigh;
  uint32_t baseMemBlock;
  int32_t  addressSpaceOwner;
  uint32_t PVECTOR;
  uint32_t roundupUnitSize;
  uint32_t domain;
  uint32_t field_34;
  uint32_t field_38;
  uint32_t field_3C;
  uint32_t field_40;
  uint32_t field_44;
  uint32_t field_48;
  uint32_t field_4C;
  uint32_t field_50;
  uint32_t field_54;
} __attribute__((packed)) SceKernelAllocMemBlockKernelOpt;

typedef struct SceModuleDecryptContext {
  void *header;
  uint32_t header_len;
  Elf32_Ehdr *elf_ehdr;
  Elf32_Phdr *elf_phdr;
  uint8_t type;
  uint8_t init_completed;
  uint8_t field_12;
  uint8_t field_13;
  SceModuleSelfSectionInfo *section_info;
  void *header_buffer;
  uint32_t sbl_ctx;
  uint32_t field_20;
  uint32_t fd;
  int32_t pid;
  uint32_t max_size;
} __attribute__((packed)) SceModuleDecryptContext;

// firmware specific function offsets
static void *(*const memset)(void *dst, int ch, int sz) = (void*)0x51013C41;
static void *(*const memcpy)(void *dst, const void *src, int sz) = (void *)0x51013BC1;
static void *(*const memmove)(void *dst, const void *src, int sz) = (void *)0x5102152D;
static void (*const clean_dcache)(void *dst, int len) = (void*)0x510146DD;
static void (*const flush_icache)() = (void*)0x51014691;
static int (*const strncmp)(const char *s1, const char *s2, int len) = (void *)0x51013CA0;
static SceObject *(*const get_obj_for_uid)(int uid) = (void *)0x51017785;
static int (*const module_load)(const SceModuleLoadList *list, SceUID *uids, int count, int) = (void *)0x51001551;
static int (*const module_load_direct)(const SceModuleLoadList *list, SceUID *uids, int count, int osloc, int unk) = (void *)0x5100148d;
static int (*const sceKernelAllocMemBlock)(const char *name, int type, unsigned size, SceKernelAllocMemBlockKernelOpt *opt) = (void *)0x51007161;
static int (*const sceKernelGetMemBlockBase)(int32_t uid, void **basep) = (void *)0x510057E1;
static int (*const sceKernelRemapBlock)(int32_t uid, int type) = (void *)0x51007171;
static int (*const sceKernelFreeMemBlock)(int32_t uid) = (void *)0x51007449;
static unsigned (*const sceKernelCpuId)(void) = (void*)(0x51014938 | 1);
static void (*const sceKernelSysrootCorelockLock)(SceUInt32 core) = (void*)(0x51012650 | 1);
static void (*const sceKernelSysrootCorelockUnlock)(void) = (void*)(0x51012668 | 1);
static void (*const sceKernelCpuSuspendIntr)(void) = (void*)(0x5101491C | 1);
static void (*const sceKernelCpuResumeIntr)(SceUInt32 state) = (void*)(0x5101492C | 1);
static SceSysroot* (*const sceKernelSysrootGetSysroot)(void) = (void*)(0x510122ec | 1);

static void (*const sceKernelSetDipsw)(uint32_t sw) = (void*)(0x510159A8 | 1);

static int (*const read_sector_mmc)(int* part_ctx, int sector, int nsectors, int buffer) = (void*)0x510010FD;
static int (*const read_sector_sd)(int* part_ctx, int sector, int buffer, int nsectors) = (void*)0x5101E879;
static int (*const sceSdStandaloneInit)(void) = (void*)0x5100124D; //called setup_emmc by Gleba
static int (*const init_part)(unsigned int *partition, unsigned int flags, unsigned int *read_func, unsigned int *master_dev) = (void*)0x5101FF21;

static int (*const iof_open)(char *fname, int flags, int mode) = (void *)0x510017D5;
static uint32_t (*const iof_lseek)(uint32_t param_1, uint32_t param_2, uint32_t param_3, uint32_t param_4, uint32_t param_5) = (void *)0x510018a9;
static int (*const iof_close)(uint32_t fdlike) = (void *)0x51001901;
static int (*const iof_read)(uint32_t fdlike, void* buf, uint32_t sizelike) = (void*)0x510209ed;

#ifdef NO_DEBUG_LOGGING
#define printf(...)
#else
static int (*const printf)(const char* fmt, ...) = (void*)0x51013919;
#endif

static int (*const snprintf)(char* buf, unsigned maxlen, const char* fmt, ...) = (void*)(0x510145c8 | 1);
static int (*const strnlen)(char* s, unsigned maxlen) = (void*)(0x51013CF0 | 1);
static char* (*const strncpy)(char* dst, const char* src, unsigned len) = (void*)(0x51014610 | 1);
static SceInt32 (*const sceKernelVAtoPA)(void* va, SceUIntPtr* ppa) = (void*)(0x5100632c | 1);
static SceUID (*const AllocMemBlockLowForKernelByCommand)(void* cmd) = (void*)(0x51006e3c | 1);
static void* (*const sceKernelSysrootGetVbaseResetVector)(void) = (void*)(0x51012420 | 1);

// firmware specific patch offsets
static SceBootArgs *const boot_args = (void *)0x51167528; //SceKblParam
static SceSysrootContext ** const sysroot_ctx_ptr = (void *)0x51138A3C;

static int (*const get_hwcfg)(uint32_t *cfgs) = (void *)0x51012a1d;

static int (*const self_auth_header)() = (void*)0x51016ea5;
static int (*const self_setup_authseg)() = (void*)0x51016f95;
static int (*const self_load_block)() = (void*)0x51016fd1;

#define NSKBL_EXPORTS_ADDR (0x5102778c)
#define NSKBL_EXPORTS(num) (NSKBL_EXPORTS_ADDR + (num * 4))

#define NSKBL_DEVICE_EMMC (0x51028010)
#define NSKBL_DEVICE_GCSD (0x5102801C)
#define NSKBL_PARTITION_OS0 (0x51167784)
#define NSKBL_PARTITION_SD0 (0x51167728)

#define dmb() __asm__ volatile("dmb #0x1F" ::: "memory")
#define dsb() __asm__ volatile("dsb #0xF" ::: "memory")

#define MODULE_START_SUCCESS 0
#define MODULE_START_NO_RESIDENT 1
#define MODULE_START_FAILED 2

#endif /* NSKBL_HEADER */