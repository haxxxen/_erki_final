#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

#define KERNEL_BASE 0x8000000000000000 //
#define KERNEL_TOC 0x34AC80 //done

#define KERNEL_SYMBOL_EXTEND_KSTACK 0x6FDA4 // 

#define KERNEL_SYMBOL_MEMSET 0x51D9C // 
#define KERNEL_SYMBOL_MEMCPY 0x8039C // 

#define KERNEL_SYMBOL_COPY_TO_USER      0xFCEC // 

#endif