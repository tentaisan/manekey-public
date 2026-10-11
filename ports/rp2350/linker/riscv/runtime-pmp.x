/* RP2350 Hazard3 linker layout, based on rp-hal's rp235x_riscv.x.
 */
MEMORY {
    FLASH : ORIGIN = DEFINED(__pmp_flash_origin) ? __pmp_flash_origin : 0x10000000,
            LENGTH = DEFINED(__pmp_flash_length) ? __pmp_flash_length : 4M
    RAM   : ORIGIN = DEFINED(__pmp_ram_origin) ? __pmp_ram_origin : 0x20000000,
            LENGTH = DEFINED(__pmp_ram_length) ? __pmp_ram_length : 512K
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

PROVIDE(_stext = ORIGIN(FLASH));
PROVIDE(_stack_start = ORIGIN(RAM) + LENGTH(RAM));
PROVIDE(_max_hart_id = 0);
PROVIDE(_hart_stack_size = 2K);
PROVIDE(_heap_size = 0);
PROVIDE(__riscv_storage_start = 0x103fc000);

PROVIDE(InstructionMisaligned = ExceptionHandler);
PROVIDE(InstructionFault = ExceptionHandler);
PROVIDE(IllegalInstruction = ExceptionHandler);
PROVIDE(Breakpoint = ExceptionHandler);
PROVIDE(LoadMisaligned = ExceptionHandler);
PROVIDE(LoadFault = ExceptionHandler);
PROVIDE(StoreMisaligned = ExceptionHandler);
PROVIDE(StoreFault = ExceptionHandler);
PROVIDE(UserEnvCall = ExceptionHandler);
PROVIDE(SupervisorEnvCall = ExceptionHandler);
PROVIDE(MachineEnvCall = ExceptionHandler);
PROVIDE(InstructionPageFault = ExceptionHandler);
PROVIDE(LoadPageFault = ExceptionHandler);
PROVIDE(StorePageFault = ExceptionHandler);
PROVIDE(SupervisorSoft = DefaultHandler);
PROVIDE(MachineSoft = DefaultHandler);
PROVIDE(SupervisorTimer = DefaultHandler);
PROVIDE(MachineTimer = DefaultHandler);
PROVIDE(SupervisorExternal = DefaultHandler);
PROVIDE(MachineExternal = DefaultHandler);
PROVIDE(DefaultHandler = DefaultInterruptHandler);
PROVIDE(ExceptionHandler = DefaultExceptionHandler);
PROVIDE(__pre_init = default_pre_init);
PROVIDE(_setup_interrupts = default_setup_interrupts);

PROVIDE(TIMER0_IRQ_0 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_1 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_2 = DefaultIrqHandler);
PROVIDE(TIMER0_IRQ_3 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_0 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_1 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_2 = DefaultIrqHandler);
PROVIDE(TIMER1_IRQ_3 = DefaultIrqHandler);
PROVIDE(PWM_IRQ_WRAP_0 = DefaultIrqHandler);
PROVIDE(PWM_IRQ_WRAP_1 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_0 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_1 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_2 = DefaultIrqHandler);
PROVIDE(DMA_IRQ_3 = DefaultIrqHandler);
PROVIDE(USBCTRL_IRQ = DefaultIrqHandler);
PROVIDE(PIO0_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO0_IRQ_1 = DefaultIrqHandler);
PROVIDE(PIO1_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO1_IRQ_1 = DefaultIrqHandler);
PROVIDE(PIO2_IRQ_0 = DefaultIrqHandler);
PROVIDE(PIO2_IRQ_1 = DefaultIrqHandler);
PROVIDE(IO_IRQ_BANK0 = DefaultIrqHandler);
PROVIDE(IO_IRQ_BANK0_NS = DefaultIrqHandler);
PROVIDE(IO_IRQ_QSPI = DefaultIrqHandler);
PROVIDE(IO_IRQ_QSPI_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_FIFO = DefaultIrqHandler);
PROVIDE(SIO_IRQ_BELL = DefaultIrqHandler);
PROVIDE(SIO_IRQ_FIFO_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_BELL_NS = DefaultIrqHandler);
PROVIDE(SIO_IRQ_MTIMECMP = DefaultIrqHandler);
PROVIDE(CLOCKS_IRQ = DefaultIrqHandler);
PROVIDE(SPI0_IRQ = DefaultIrqHandler);
PROVIDE(SPI1_IRQ = DefaultIrqHandler);
PROVIDE(UART0_IRQ = DefaultIrqHandler);
PROVIDE(UART1_IRQ = DefaultIrqHandler);
PROVIDE(ADC_IRQ_FIFO = DefaultIrqHandler);
PROVIDE(I2C0_IRQ = DefaultIrqHandler);
PROVIDE(I2C1_IRQ = DefaultIrqHandler);
PROVIDE(OTP_IRQ = DefaultIrqHandler);
PROVIDE(TRNG_IRQ = DefaultIrqHandler);
PROVIDE(PLL_SYS_IRQ = DefaultIrqHandler);
PROVIDE(PLL_USB_IRQ = DefaultIrqHandler);
PROVIDE(POWMAN_IRQ_POW = DefaultIrqHandler);
PROVIDE(POWMAN_IRQ_TIMER = DefaultIrqHandler);
PROVIDE(SW0_IRQ = DefaultIrqHandler);
PROVIDE(SW1_IRQ = DefaultIrqHandler);
PROVIDE(SW2_IRQ = DefaultIrqHandler);
PROVIDE(SW3_IRQ = DefaultIrqHandler);
PROVIDE(SW4_IRQ = DefaultIrqHandler);
PROVIDE(SW5_IRQ = DefaultIrqHandler);
PROVIDE(_mp_hook = default_mp_hook);
PROVIDE(_start_trap = default_start_trap);

SECTIONS {
  .text.dummy (NOLOAD) : { . = ABSOLUTE(_stext); } > FLASH

  .text _stext : {
    KEEP(*(.init));
    KEEP(*(.init.rust));
    . = ALIGN(4);
    __start_block_addr = .;
    KEEP(*(.start_block));
    KEEP(*(.boot_info));
    . = ALIGN(4);
    *(.trap);
    *(.trap.rust);
    *(.text.abort);
    . = ALIGN(32);
    __pmp_machine_text_start = .;
    KEEP(*(.text.pmp_machine_preflight));
    . = ALIGN(32);
    __pmp_machine_text_end = .;
    . = ALIGN(65536);
    __pmp_user_text_start = .;
    KEEP(*(.text.pmp_user*));
    KEEP(*(.rodata.pmp_user*));
    . = ALIGN(65536);
    __pmp_user_text_end = .;
    *(.text .text.*);
    . = ALIGN(4);
  } > FLASH

  .bi_entries : ALIGN(4) {
    __bi_entries_start = .;
    KEEP(*(.bi_entries));
    . = ALIGN(4);
    __bi_entries_end = .;
  } > FLASH

  .rodata : ALIGN(4) {
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    . = ALIGN(4);
  } > FLASH

  .data : ALIGN(32) {
    _sidata = LOADADDR(.data);
    __sidata = LOADADDR(.data);
    _sdata = .;
    __sdata = .;
    PROVIDE(__global_pointer$ = . + 0x800);
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    . = ALIGN(32);
    __pmp_machine_data_start = .;
    KEEP(*(.data.pmp_machine_protected));
    . = ALIGN(32);
    __pmp_machine_data_end = .;
    . = ALIGN(4);
    __riscv_ram_func_start = .;
    KEEP(*(.data.ram_func .data.ram_func.*));
    . = ALIGN(4);
    __riscv_ram_func_end = .;
    *(.data .data.*);
    . = ALIGN(32);
    _edata = .;
    __edata = .;
  } > RAM AT > FLASH

  .bss (NOLOAD) : ALIGN(32) {
    _sbss = .;
    *(.sbss .sbss.* .bss);
    . = ALIGN(DEFINED(__pmp_shared_alignment) ? __pmp_shared_alignment : 8192);
    __pmp_shared_start = .;
    KEEP(*(.bss.pmp_shared));
    . = ALIGN(DEFINED(__pmp_shared_alignment) ? __pmp_shared_alignment : 8192);
    __pmp_shared_end = .;
    . = ALIGN(DEFINED(__pmp_user_stack_alignment) ? __pmp_user_stack_alignment : 8192);
    __pmp_user_stack_start = .;
    KEEP(*(.bss.pmp_user_stack));
    . = ALIGN(DEFINED(__pmp_user_stack_alignment) ? __pmp_user_stack_alignment : 8192);
    __pmp_user_stack_end = .;
    . = ALIGN(8192);
    __pmp_machine_trap_stack_start = .;
    KEEP(*(.bss.pmp_machine_trap_stack));
    . = ALIGN(8192);
    __pmp_machine_trap_stack_end = .;
    . = ALIGN(8192);
    __pmp_user_async_start = .;
    KEEP(*(.bss.pmp_user_async));
    . = ALIGN(8192);
    __pmp_user_async_end = .;
    *(.bss.*);
    . = ALIGN(32);
    _ebss = .;
  } > RAM

  .end_block : ALIGN(4) {
    __end_block_addr = .;
    KEEP(*(.end_block));
    __flash_binary_end = .;
  } > FLASH

  .heap (NOLOAD) : {
    _sheap = .;
    . += _heap_size;
    . = ALIGN(4);
    _eheap = .;
  } > RAM

  .stack (NOLOAD) : {
    _estack = .;
    . = ABSOLUTE(_stack_start);
    _sstack = .;
  } > RAM

  .got (INFO) : { KEEP(*(.got .got.*)); }
  .eh_frame (INFO) : { KEEP(*(.eh_frame)) }
  .eh_frame_hdr (INFO) : { *(.eh_frame_hdr) }
}

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

ASSERT(ORIGIN(FLASH) % 4 == 0, "FLASH must be 4-byte aligned");
ASSERT(ORIGIN(RAM) % 32 == 0, "RAM must be 32-byte aligned");
ASSERT(_sdata % 32 == 0 && _edata % 32 == 0, ".data must be 32-byte aligned");
ASSERT(_sidata % 32 == 0, ".data load address must be 32-byte aligned");
ASSERT(__riscv_ram_func_start % 4 == 0 && __riscv_ram_func_end % 4 == 0,
       "RISC-V RAM functions must be 4-byte aligned");
ASSERT(_sbss % 32 == 0 && _ebss % 32 == 0, ".bss must be 32-byte aligned");
ASSERT(SIZEOF(.stack) > (_max_hart_id + 1) * _hart_stack_size, "stack too small");
ASSERT(SIZEOF(.stack) >= (DEFINED(__riscv_min_main_stack) ? __riscv_min_main_stack : 0),
       "RISC-V managed initialization stack budget is insufficient");
ASSERT(SIZEOF(.got) == 0, ".got section detected");
ASSERT(__pmp_user_stack_start % (DEFINED(__pmp_user_stack_alignment) ? __pmp_user_stack_alignment : 8192) == 0,
       "PMP U stack alignment mismatch");
ASSERT(__pmp_user_stack_end == __pmp_user_stack_start ||
       __pmp_user_stack_end - __pmp_user_stack_start == (DEFINED(__pmp_user_stack_alignment) ? __pmp_user_stack_alignment : 8192),
       "PMP U stack exceeds its NAPOT region");
ASSERT(__flash_binary_end <= __riscv_storage_start, "RISC-V image overlaps flash storage");
