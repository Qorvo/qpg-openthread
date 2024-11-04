/*
 * Copyright (c) 2024, Qorvo Inc
 *
 * This software is owned by Qorvo Inc
 * and protected under applicable copyright laws.
 * It is delivered under the terms of the license
 * and is intended and supplied for use solely and
 * exclusively with products manufactured by
 * Qorvo Inc.
 *
 *
 * THIS SOFTWARE IS PROVIDED IN AN "AS IS"
 * CONDITION. NO WARRANTIES, WHETHER EXPRESS,
 * IMPLIED OR STATUTORY, INCLUDING, BUT NOT
 * LIMITED TO, IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE APPLY TO THIS SOFTWARE.
 * QORVO INC. SHALL NOT, IN ANY
 * CIRCUMSTANCES, BE LIABLE FOR SPECIAL,
 * INCIDENTAL OR CONSEQUENTIAL DAMAGES,
 * FOR ANY REASON WHATSOEVER.
 *
 */




/* Memory Spaces Definitions */
MEMORY
{
    /* NRT CODE range is limited, because of reserved space for the secure element code */
    CODE_NRT (rx)   : ORIGIN = 0x10013000, LENGTH = 0x1eb000
    UCRAM (rxw)     : ORIGIN = 0x20000000, LENGTH = 0x48000
    SYSRAM (rxw)    : ORIGIN = 0x40000000, LENGTH = 0x4000
    AKRAM_NRT (rxw) : ORIGIN = 0x42038000, LENGTH = 0x4800
}

SECTIONS
{
    eFLASH = ORIGIN(CODE_NRT) + LENGTH(CODE_NRT);
    eSYSRAM = ORIGIN(SYSRAM) + LENGTH(SYSRAM);
    eUCRAM  = ORIGIN(UCRAM) + LENGTH(UCRAM);
    sUCRAM  = ORIGIN(UCRAM);

    .appuc_fw_header  : { KEEP(*(.appuc_fw_header)); } > CODE_NRT
    .isr_vector : ALIGN(0x100) { KEEP(*(.isr_vector)); } > CODE_NRT


    rt_system_start_offset = 0x13400;
    .rt_flash    0x10013400  : {. = ALIGN(4); *(.rt_flash);    } > CODE_NRT

    .text :
    {
        . = ALIGN(4);
        *(.text) *(.text.*)

        KEEP(*(.init))
        KEEP(*(.fini))

        /* .ctors */
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)

        /* .dtors */
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)

        *(.rodata) *(.rodata.*)
        KEEP(*(.eh_frame*))
    } > CODE_NRT

    .ARM.extab :
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > CODE_NRT

    __exidx_start = .;
    .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > CODE_NRT
    __exidx_end = .;

    /* Start of memory to be retained in sleep */
    _sretain = 0x40000000;

    .retain_header ORIGIN(SYSRAM) : { . += 0x10; } > SYSRAM
    .cal_ram_regmap ADDR(.retain_header) + SIZEOF(.retain_header) : { . += 0x100; } > SYSRAM
    .retain_body ADDR(.cal_ram_regmap) + SIZEOF(.cal_ram_regmap) : { . += 0x400; } > SYSRAM
    .esevents 0x40000600 : { . += 0x100; } >  SYSRAM
    .sysram (NOLOAD) :
    {
        . = ALIGN(4);
        *(.lower_ram_retain) *(.lower_ram_retain.*);
        *(.sysram);

    } > SYSRAM
    sysram_end = . ;


    /* Check regions are allocated in lower ram */
    ASSERT(sysram_end < eSYSRAM, "SYSRAM ram full")

    /* Reserve space for the (Akuma) IPC command parameters */
    .rt_cmd_ 0x42038220 : { . += 0xc; } > AKRAM_NRT
    /* Reserve space for the regmaps */
    /* Keep the default for now (from AK_MM_RAM_REGMAP_BASE_ADDRESS) - but optimize in SDP004-3060 */
    .fixed_ram_regmaps 0x42038500 : { . += 0x400; } > AKRAM_NRT

    /* Put all sections marked with .rt_fast_ram in Akuma RAM (as it will yield faster accesses on the M0 processor) */
    .rt_fast_ram (NOLOAD) : { . = ALIGN(4); *(.rt_fast_ram) *(.rt_fast_ram.*); *(.lower_ram_retain_gpmicro_accessible) *(.lower_ram_retain_gpmicro_accessible.*); } > AKRAM_NRT
    _akram_end = . ;

    /* Start of appuc memory to be retained in sleep */
    _sretain = 0x20000000;

    .data :
    {
        __data_start__ = .;
        *(vtable)
        . = ALIGN (4);
        *(.data) *(.data.*)
        PROVIDE (__ram_func_section_start = .);
        *(.ram)
        PROVIDE (__ram_func_section_end = .);

        . = ALIGN(4);
        /* preinit data */
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        /* init data */
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        /* finit data */
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE_HIDDEN (__fini_array_end = .);

        KEEP(*(.jcr*))
        . = ALIGN(4);
        /* All data end */
        __data_end__ = .;
    } > UCRAM AT > CODE_NRT
    .bss :  { . = ALIGN(4); *(.bss)  *(.bss.*) *(COMMON); } > UCRAM

    /* setting a minimum heap size maximises heap and reduces stack */
    __dyn_heap_start    = ALIGN(4);
    __dyn_heap_end      = ORIGIN(UCRAM) + LENGTH(UCRAM) - ALIGN(0x800,4);
    __dyn_heap_size     =  __dyn_heap_end - __dyn_heap_start;
    ASSERT(__dyn_heap_size >= 0x8000, "HEAP too small")
    .heap   (NOLOAD) :    ALIGN(4)        { . = ALIGN(4); . += __dyn_heap_size; } > UCRAM

    /* End of memory to be retained */
    _eretain = . ;

    /* Scroll up to higher ram area for scratchpad variables */
    .higher_ram_noretain (NOLOAD) : {
        . = (_eretain > sUCRAM) ? ALIGN(4) : (sUCRAM - _eretain);
        _shigher_ram_noretain = . ;
        *(.higher_ram_noretain) *(.higher_ram_noretain.*);
        _ehigher_ram_noretain = . ;
    } > UCRAM
    /* Check if properly allocated in UCRAM only if any variables required specific allocation. */
    ASSERT((_ehigher_ram_noretain - _shigher_ram_noretain) > 0 ? (_shigher_ram_noretain >= sUCRAM) : 1, "higher_ram_noretain not in higher ram")

    _eram = .;

   /* Remove the debugging information from the standard libraries */
    /DISCARD/ : {
        libc.a ( * )
        libm.a ( * )
        libgcc.a ( * )
    }

    .gpNvm eFLASH - 0x4000:
    {
        gpNvm_Start = . ;
        KEEP(*(gpNvm.data));
        .  = gpNvm_Start + 0x4000;
        gpNvm_End = . ;
    } > CODE_NRT
    /* Linker Symbols */
    _sappuc_fw_header   = ADDR(.appuc_fw_header);
    _fw_header_vpp    = ADDR(.isr_vector) >> 8;
    _loaded_user_license_vpp    = ADDR(.isr_vector) >> 8;
    _etext  = ADDR(.text) + SIZEOF(.text);
    _sidata = LOADADDR(.data);
    _sdata  = ADDR(.data);
    _edata  = ADDR(.data) + ALIGN(SIZEOF(.data), 4);
    _ldata  = _edata - _sdata;
    _sbss   = ADDR(.bss);
    _ebss   = ADDR(.bss)  + ALIGN(SIZEOF(.bss),  4);
    _lbss   = _ebss - _sbss;
    __sysram_retain_header_start = ADDR(.retain_header);
    __sysram_retain_header_end = ADDR(.retain_header) + SIZEOF(.retain_header);
    __sysram_retain_body_start = ADDR(.retain_body);
    __sysram_retain_body_end = ADDR(.retain_body) + SIZEOF(.retain_body);
    __sysram_esevents_start = ADDR(.esevents);
    __sysram_esevents_end = ADDR(.esevents) + SIZEOF(.esevents);
    _sysram_start = ORIGIN(SYSRAM);
    _sysram_length = sysram_end - _sysram_start;
    _akram_start = ORIGIN(AKRAM_NRT);
    _akram_length = _akram_end - _akram_start;
    _sheap  = ADDR(.heap);
    _eheap  = ADDR(.heap)  + ALIGN(SIZEOF(.heap),  4);
    _lheap  = _eheap - _sheap;

    /* stack size is a constant */
    _sstack = __dyn_heap_end;

    _estack = ORIGIN(UCRAM) + LENGTH(UCRAM);
    _lstack = _estack - _sstack;

    /* check minimum stack size is still available */
    min_stack_size = 0x800;
    stack_size     = _estack - _sstack;
    ASSERT(stack_size >= min_stack_size, "STACK too small")

    /* needed for ram retention configuration */
    __appuc_ram_retain_length    = _eretain - _sretain;

}

ENTRY(reset_handler)
