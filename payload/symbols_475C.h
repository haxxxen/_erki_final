#ifndef __SYMBOLS_H__
#define __SYMBOLS_H__

#define KERNEL_BASE 0x8000000000000000 //
#define KERNEL_TOC 0x34FBB0 //done
#define KERNEL_SYSCALL_TABLE 0x363BE0 //done

#define KERNEL_SYMBOL_EXTEND_KSTACK 0x700A4 // 

#define KERNEL_SYMBOL_ALLOCATE   0x64824 // 
#define KERNEL_SYMBOL_DEALLOCATE 0x64C60 // 

#define KERNEL_SYMBOL_PAGE_ALLOCATE              0x60394 // 
#define KERNEL_SYMBOL_PAGE_DEALLOCATE            0x4348 //
#define KERNEL_SYMBOL_PAGE_EXPORT_TO_PROCESS     0x60530 // 
#define KERNEL_SYMBOL_PAGE_UNEXPORT_FROM_PROCESS 0x5FCEC // 

#define KERNEL_SYMBOL_CREATE_MEMORY_CONTAINER  0x272604 //IDA confirmed
#define KERNEL_SYMBOL_DESTROY_MEMORY_CONTAINER 0x272080 // IDA confirmed

#define KERNEL_SYMBOL_MEMSET 0x4D66C // 
#define KERNEL_SYMBOL_MEMCPY 0x7E92C // 
#define KERNEL_SYMBOL_MEMCHR 0x4C92C // 
#define KERNEL_SYMBOL_MEMCMP 0x4C97C // 

#define KERNEL_SYMBOL_STRLEN   0x4D840 // 
#define KERNEL_SYMBOL_STRCPY   0x4D818 //
#define KERNEL_SYMBOL_STRNCPY  0x4D8E0 // 
#define KERNEL_SYMBOL_STRCAT   0x4D748 // 
#define KERNEL_SYMBOL_STRCHR   0x4D780 // 
#define KERNEL_SYMBOL_STRRCHR  0x4D950 // 
#define KERNEL_SYMBOL_STRCMP   0x4D7C4 // 
#define KERNEL_SYMBOL_STRNCMP  0x4D86C //

#define KERNEL_SYMBOL_PRINTF    0x2706AC // IDA confirmed
#define KERNEL_SYMBOL_SPRINTF   0x4EA94 // 
#define KERNEL_SYMBOL_SNPRINTF  0x4EA00 // 
#define KERNEL_SYMBOL_VSNPRINTF 0x4EB64 // 

#define KERNEL_SYMBOL_FS_OPEN_1 0x297B34 //IDA confirmed
#define KERNEL_SYMBOL_FS_OPEN_2 0x297900 // IDA confirmed
#define KERNEL_SYMBOL_FS_READ   0x2978A4 // IDA confirmed
#define KERNEL_SYMBOL_FS_WRITE  0x297810 // IDA confirmed
#define KERNEL_SYMBOL_FS_LSEEK  0x296E98 // IDA confirmed
#define KERNEL_SYMBOL_FS_STAT   0x29711C // IDA confirmed
#define KERNEL_SYMBOL_FS_CLOSE  0x29BD7C // IDA confirmed

#define KERNEL_SYMBOL_PPU_THREAD_CREATE 0x13EC8 // 
#define KERNEL_SYMBOL_PPU_THREAD_JOIN   0x13FD4 // 
#define KERNEL_SYMBOL_PPU_THREAD_DELAY  0x287A4 // 
#define KERNEL_SYMBOL_PPU_THREAD_EXIT   0x13F80 // 

#define KERNEL_SYMBOL_CREATE_USER_THREAD1 0x2525C // 
#define KERNEL_SYMBOL_CREATE_USER_THREAD2 0x25080 // 
#define KERNEL_SYMBOL_REGISTER_THREAD     0x26794C // IDA confirmed
#define KERNEL_SYMBOL_START_THREAD        0x23D4C // 
#define KERNEL_SYMBOL_RUN_THREAD          0x2357C // 

#define KERNEL_SYMBOL_ALLOCATE_USER_STACK   0x268134 // IDA confirmed
#define KERNEL_SYMBOL_DEALLOCATE_USER_STACK 0x26809C // IDA confirmed

#define KERNEL_SYMBOL_COPY_FROM_USER    0xFA88 // 
#define KERNEL_SYMBOL_COPY_TO_USER      0xF86C // 
#define KERNEL_SYMBOL_COPY_FROM_PROCESS 0xF734 // 
#define KERNEL_SYMBOL_COPY_TO_PROCESS   0xF924 // 

#define KERNEL_SYMBOL_ID_TABLE_RESERVE_ID   0x8CD1C // 
#define KERNEL_SYMBOL_ID_TABLE_UNRESERVE_ID 0x11914 // 

#define KERNEL_SYMBOL_GET_OBJECT_COUNT 0x11410 // 
#define KERNEL_SYMBOL_GET_OBJECTS      0x11488 //

#define KERNEL_SYMBOL_PROCESS_SUB_8000000000003B38 0x3B38 //

#define KERNEL_SYMBOL_PROCESS_READ_MEMORY                   0x267EC0 // IDA confirmed
#define KERNEL_SYMBOL_PROCESS_WRITE_MEMORY_EX               0x267D34 // IDA confirmed
#define KERNEL_SYMBOL_PROCESS_GET_INTERNAL_PPU_THREAD_COUNT 0x242C8 // 
#define KERNEL_SYMBOL_PROCESS_GET_PARENT_PID                0x269500 // IDA confirmed
#define KERNEL_SYMBOL_PROCESS_ALLOCATE_MAPPED_MEMORY_EX     0x76B78 // 

#define KERNEL_SYMBOL_PRX_LOAD_MODULE   0x88C04 // 
#define KERNEL_SYMBOL_PRX_START_MODULE  0x878D0 // 
#define KERNEL_SYMBOL_PRX_STOP_MODULE   0x88CA8 //
#define KERNEL_SYMBOL_PRX_UNLOAD_MODULE 0x87604 // 

#define KERNEL_SYMBOL_PRX_GET_MODULE_INFO          0x8708C // 
#define KERNEL_SYMBOL_PRX_GET_MODULE_ID_BY_ADDRESS 0x86F9C // 
#define KERNEL_SYMBOL_PRX_GET_MODULE_ID_BY_NAME    0x86FEC // 
#define KERNEL_SYMBOL_PRX_GET_MODULE_LIST          0x8710C // 

#define KERNEL_SYMBOL_KERNEL_EA_TO_LPAR_ADDR     0x7014C //
#define KERNEL_SYMBOL_PROCESS_EA_TO_LPAR_ADDR_EX 0x77760 // 
#define KERNEL_SYMBOL_MAP_CONTIGUOUS_MEMORY      0x76538 //
#define KERNEL_SYMBOL_UNMAP_CONTIGUOUS_MEMORY    0x763B0 // 

#define KERNEL_SYMBOL_SPIN_LOCK_IRQSAVE_EX    0x26D798 // 
#define KERNEL_SYMBOL_SPIN_LOCK_IRQRESTORE_EX 0x26D76C // 

#define KERNEL_SYMBOL_PANIC 0x26D5C8 // 

#define KERNEL_SYMBOL_SYS_PROCESS_GETPID 0x1A214 // 
#define KERNEL_SYMBOL_SYS_PROCESS_EXIT   0x1A4E4 // 

#define KERNEL_SYMBOL_PROC_ID_TABLE_PTR 0x475680 //

#endif