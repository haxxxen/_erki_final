#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

#define KERNEL_BASE 0x8000000000000000
#define KERNEL_TOC 0x375510 //0x34B160

#define KERNEL_SYMBOL_EXTEND_KSTACK 0x73B6C //0x6E7C0

#define KERNEL_SYMBOL_MEMSET 0x51014 //0x4D490
#define KERNEL_SYMBOL_MEMCPY 0x82980 //0x7D048

#define KERNEL_SYMBOL_COPY_TO_USER      0xFEB4 //0xF858

#endif