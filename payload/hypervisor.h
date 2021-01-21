#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#ifndef __ASSEMBLY__
	#include "common.h"

	#define HYPERVISOR_SUCCESS                 (0)
	#define HYPERVISOR_RESOURCE_SHORTAGE       (-2)
	#define HYPERVISOR_NO_PRIVILEGE            (-3)
	#define HYPERVISOR_DENIED_BY_POLICY        (-4)
	#define HYPERVISOR_ACCESS_VIOLATION        (-5)
	#define HYPERVISOR_NO_ENTRY                (-6)
	#define HYPERVISOR_ILLEGAL_PARAMETER_VALUE (-17)
	#define HYPERVISOR_NOT_IMPLEMENTED         (-20)
	#define HYPERVISOR_ALIGNMENT_ERROR         (-23)

	#define HYPERVISOR_1_IN_ARG_DECL uint64_t in_1
	#define HYPERVISOR_2_IN_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, uint64_t in_2
	#define HYPERVISOR_3_IN_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, uint64_t in_3
	#define HYPERVISOR_4_IN_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, uint64_t in_4
	#define HYPERVISOR_5_IN_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, uint64_t in_5
	#define HYPERVISOR_6_IN_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, uint64_t in_6
	#define HYPERVISOR_7_IN_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, uint64_t in_7
	#define HYPERVISOR_8_IN_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, uint64_t in_8

	#define HYPERVISOR_1_OUT_ARG_DECL uint64_t *out_1
	#define HYPERVISOR_2_OUT_ARG_DECL HYPERVISOR_1_OUT_ARG_DECL, uint64_t *out_2
	#define HYPERVISOR_3_OUT_ARG_DECL HYPERVISOR_2_OUT_ARG_DECL, uint64_t *out_3
	#define HYPERVISOR_4_OUT_ARG_DECL HYPERVISOR_3_OUT_ARG_DECL, uint64_t *out_4
	#define HYPERVISOR_5_OUT_ARG_DECL HYPERVISOR_4_OUT_ARG_DECL, uint64_t *out_5
	#define HYPERVISOR_6_OUT_ARG_DECL HYPERVISOR_5_OUT_ARG_DECL, uint64_t *out_6
	#define HYPERVISOR_7_OUT_ARG_DECL HYPERVISOR_6_OUT_ARG_DECL, uint64_t *out_7

	#define HYPERVISOR_0_IN_0_OUT_ARG_DECL void
	#define HYPERVISOR_1_IN_0_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL
	#define HYPERVISOR_2_IN_0_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL
	#define HYPERVISOR_3_IN_0_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL
	#define HYPERVISOR_4_IN_0_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL
	#define HYPERVISOR_5_IN_0_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL
	#define HYPERVISOR_6_IN_0_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL
	#define HYPERVISOR_7_IN_0_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL

	#define HYPERVISOR_0_IN_1_OUT_ARG_DECL HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_1_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_1_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_1_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_1_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_1_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_1_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_1_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
	#define HYPERVISOR_8_IN_1_OUT_ARG_DECL HYPERVISOR_8_IN_ARG_DECL, HYPERVISOR_1_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_2_OUT_ARG_DECL HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_2_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_2_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_2_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_2_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_2_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_2_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_2_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_2_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_3_OUT_ARG_DECL HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_3_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_3_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_3_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_3_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_3_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_3_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_3_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_3_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_4_OUT_ARG_DECL HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_4_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_4_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_4_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_4_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_4_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_4_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_4_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_4_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_5_OUT_ARG_DECL HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_5_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_5_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_5_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_5_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_5_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_5_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_5_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_5_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_6_OUT_ARG_DECL HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_6_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_6_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_6_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_6_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_6_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_6_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_6_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_6_OUT_ARG_DECL
                                    
	#define HYPERVISOR_0_IN_7_OUT_ARG_DECL HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_1_IN_7_OUT_ARG_DECL HYPERVISOR_1_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_2_IN_7_OUT_ARG_DECL HYPERVISOR_2_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_3_IN_7_OUT_ARG_DECL HYPERVISOR_3_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_4_IN_7_OUT_ARG_DECL HYPERVISOR_4_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_5_IN_7_OUT_ARG_DECL HYPERVISOR_5_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_6_IN_7_OUT_ARG_DECL HYPERVISOR_6_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL
	#define HYPERVISOR_7_IN_7_OUT_ARG_DECL HYPERVISOR_7_IN_ARG_DECL, HYPERVISOR_7_OUT_ARG_DECL

	#define HYPERVISOR_1_IN_ARGS in_1
	#define HYPERVISOR_2_IN_ARGS HYPERVISOR_1_IN_ARGS, in_2
	#define HYPERVISOR_3_IN_ARGS HYPERVISOR_2_IN_ARGS, in_3
	#define HYPERVISOR_4_IN_ARGS HYPERVISOR_3_IN_ARGS, in_4
	#define HYPERVISOR_5_IN_ARGS HYPERVISOR_4_IN_ARGS, in_5
	#define HYPERVISOR_6_IN_ARGS HYPERVISOR_5_IN_ARGS, in_6
	#define HYPERVISOR_7_IN_ARGS HYPERVISOR_6_IN_ARGS, in_7
	#define HYPERVISOR_8_IN_ARGS HYPERVISOR_7_IN_ARGS, in_8

	#define HYPERVISOR_1_OUT_ARGS out_1
	#define HYPERVISOR_2_OUT_ARGS HYPERVISOR_1_OUT_ARGS, out_2
	#define HYPERVISOR_3_OUT_ARGS HYPERVISOR_2_OUT_ARGS, out_3
	#define HYPERVISOR_4_OUT_ARGS HYPERVISOR_3_OUT_ARGS, out_4
	#define HYPERVISOR_5_OUT_ARGS HYPERVISOR_4_OUT_ARGS, out_5
	#define HYPERVISOR_6_OUT_ARGS HYPERVISOR_5_OUT_ARGS, out_6
	#define HYPERVISOR_7_OUT_ARGS HYPERVISOR_6_OUT_ARGS, out_7

	#define HYPERVISOR_0_IN_0_OUT_ARGS 
	#define HYPERVISOR_1_IN_0_OUT_ARGS HYPERVISOR_1_IN_ARGS
	#define HYPERVISOR_2_IN_0_OUT_ARGS HYPERVISOR_2_IN_ARGS
	#define HYPERVISOR_3_IN_0_OUT_ARGS HYPERVISOR_3_IN_ARGS
	#define HYPERVISOR_4_IN_0_OUT_ARGS HYPERVISOR_4_IN_ARGS
	#define HYPERVISOR_5_IN_0_OUT_ARGS HYPERVISOR_5_IN_ARGS
	#define HYPERVISOR_6_IN_0_OUT_ARGS HYPERVISOR_6_IN_ARGS
	#define HYPERVISOR_7_IN_0_OUT_ARGS HYPERVISOR_7_IN_ARGS
                                
	#define HYPERVISOR_0_IN_1_OUT_ARGS HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_1_IN_1_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_2_IN_1_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_3_IN_1_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_4_IN_1_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_5_IN_1_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_6_IN_1_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_7_IN_1_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_1_OUT_ARGS
	#define HYPERVISOR_8_IN_1_OUT_ARGS HYPERVISOR_8_IN_ARGS, HYPERVISOR_1_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_2_OUT_ARGS HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_1_IN_2_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_2_IN_2_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_3_IN_2_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_4_IN_2_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_5_IN_2_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_6_IN_2_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_2_OUT_ARGS
	#define HYPERVISOR_7_IN_2_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_2_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_3_OUT_ARGS HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_1_IN_3_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_2_IN_3_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_3_IN_3_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_4_IN_3_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_5_IN_3_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_6_IN_3_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_3_OUT_ARGS
	#define HYPERVISOR_7_IN_3_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_3_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_4_OUT_ARGS HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_1_IN_4_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_2_IN_4_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_3_IN_4_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_4_IN_4_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_5_IN_4_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_6_IN_4_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_4_OUT_ARGS
	#define HYPERVISOR_7_IN_4_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_4_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_5_OUT_ARGS HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_1_IN_5_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_2_IN_5_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_3_IN_5_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_4_IN_5_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_5_IN_5_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_6_IN_5_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_5_OUT_ARGS
	#define HYPERVISOR_7_IN_5_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_5_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_6_OUT_ARGS HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_1_IN_6_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_2_IN_6_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_3_IN_6_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_4_IN_6_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_5_IN_6_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_6_IN_6_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_6_OUT_ARGS
	#define HYPERVISOR_7_IN_6_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_6_OUT_ARGS
                                
	#define HYPERVISOR_0_IN_7_OUT_ARGS HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_1_IN_7_OUT_ARGS HYPERVISOR_1_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_2_IN_7_OUT_ARGS HYPERVISOR_2_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_3_IN_7_OUT_ARGS HYPERVISOR_3_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_4_IN_7_OUT_ARGS HYPERVISOR_4_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_5_IN_7_OUT_ARGS HYPERVISOR_5_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_6_IN_7_OUT_ARGS HYPERVISOR_6_IN_ARGS, HYPERVISOR_7_OUT_ARGS
	#define HYPERVISOR_7_IN_7_OUT_ARGS HYPERVISOR_7_IN_ARGS, HYPERVISOR_7_OUT_ARGS

	#ifndef HYPERVISOR_CALL
		#define HYPERVISOR_CALL(name, in, out, num) \
			extern int JOIN(_lv1_, name)(HYPERVISOR_##in##_IN_##out##_OUT_ARG_DECL); \
			static inline int JOIN(lv1_, name)(HYPERVISOR_##in##_IN_##out##_OUT_ARG_DECL) { \
				return JOIN(_lv1_, name)(HYPERVISOR_##in##_IN_##out##_OUT_ARGS); \
			}
	#endif

	#define LPAR_ID_PME 1

	uint64_t vas_get_id(void);

	void lv1_callv(uint64_t* regs);
#endif /* !__ASSEMBLY__ */

/*
 * HYPERVISOR_CALL(name in out number)
 */
HYPERVISOR_CALL(allocate_memory, 4, 2, 0)
HYPERVISOR_CALL(write_htab_entry, 4, 0, 1)
HYPERVISOR_CALL(construct_virtual_address_space, 3, 2, 2)
HYPERVISOR_CALL(invalidate_htab_entries, 5, 0, 3)
HYPERVISOR_CALL(get_virtual_address_space_id_of_pu, 1, 1, 4)
HYPERVISOR_CALL(query_logical_partition_address_region_info, 1, 5, 6)
HYPERVISOR_CALL(select_virtual_address_space, 1, 0, 7)
HYPERVISOR_CALL(pause, 1, 0, 9)
HYPERVISOR_CALL(destruct_virtual_address_space, 1, 0, 10)
HYPERVISOR_CALL(configure_irq_state_bitmap, 3, 0, 11)
HYPERVISOR_CALL(connect_irq_plug, 5, 0, 12)
HYPERVISOR_CALL(release_memory, 1, 0, 13)
HYPERVISOR_CALL(put_iopte, 5, 0, 15)
HYPERVISOR_CALL(disconnect_irq_plug, 3, 0, 17)
HYPERVISOR_CALL(construct_event_receive_port, 0, 1, 18)
HYPERVISOR_CALL(destruct_event_receive_port, 1, 0, 19)
HYPERVISOR_CALL(send_event_locally, 1, 0, 24)
HYPERVISOR_CALL(detect_pending_interrupts, 1, 4, 26)
HYPERVISOR_CALL(end_of_interrupt, 1, 0, 27)
HYPERVISOR_CALL(construct_and_connect_irq_plug, 2, 0, 28)
HYPERVISOR_CALL(destruct_irq_plug, 1, 0, 29)
HYPERVISOR_CALL(end_of_interrupt_ext, 3, 0, 30)
HYPERVISOR_CALL(did_update_interrupt_mask, 2, 0, 31)
HYPERVISOR_CALL(shutdown_logical_partition, 1, 0, 44)
HYPERVISOR_CALL(destruct_logical_spu, 1, 0, 54)
HYPERVISOR_CALL(construct_logical_spu, 7, 6, 57)
HYPERVISOR_CALL(set_spu_interrupt_mask, 3, 0, 61)
HYPERVISOR_CALL(set_spu_transition_notifier, 3, 0, 64)
HYPERVISOR_CALL(disable_logical_spu, 2, 0, 65)
HYPERVISOR_CALL(clear_spu_interrupt_status, 4, 0, 66)
HYPERVISOR_CALL(get_spu_interrupt_status, 2, 1, 67)
HYPERVISOR_CALL(get_logical_pu_id, 0, 1, 69)
HYPERVISOR_CALL(set_interrupt_mask, 5, 0, 73)
HYPERVISOR_CALL(get_logical_partition_id, 0, 1, 74)
HYPERVISOR_CALL(configure_execution_time_variable, 1, 0, 77)
HYPERVISOR_CALL(get_spu_irq_outlet, 2, 1, 78)
HYPERVISOR_CALL(set_spu_privilege_state_area_1_register, 3, 0, 79)
HYPERVISOR_CALL(create_repository_node, 6, 0, 90)
HYPERVISOR_CALL(get_repository_node_value, 5, 2, 91)
HYPERVISOR_CALL(modify_repository_node_value, 6, 0, 92)
HYPERVISOR_CALL(remove_repository_node, 4, 0, 93)
HYPERVISOR_CALL(read_htab_entries, 2, 5, 95)
HYPERVISOR_CALL(set_dabr, 2, 0, 96)
HYPERVISOR_CALL(set_vmx_graphics_mode, 1, 0, 97)
HYPERVISOR_CALL(set_thread_switch_control_register, 1, 0, 98)
HYPERVISOR_CALL(get_total_execution_time, 2, 1, 103)
HYPERVISOR_CALL(undocumented_function_114, 3, 1, 114)
HYPERVISOR_CALL(undocumented_function_115, 1, 0, 115)
HYPERVISOR_CALL(allocate_io_segment, 3, 1, 116)
HYPERVISOR_CALL(release_io_segment, 2, 0, 117)
HYPERVISOR_CALL(allocate_ioid, 1, 1, 118)
HYPERVISOR_CALL(release_ioid, 2, 0, 119)
HYPERVISOR_CALL(construct_io_irq_outlet, 1, 1, 120)
HYPERVISOR_CALL(destruct_io_irq_outlet, 1, 0, 121)
HYPERVISOR_CALL(map_htab, 1, 1, 122)
HYPERVISOR_CALL(unmap_htab, 1, 0, 123)
HYPERVISOR_CALL(get_version_info, 0, 1, 127)
HYPERVISOR_CALL(insert_htab_entry, 6, 3, 158)
HYPERVISOR_CALL(read_virtual_uart, 3, 1, 162)
HYPERVISOR_CALL(write_virtual_uart, 3, 1, 163)
HYPERVISOR_CALL(set_virtual_uart_param, 3, 0, 164)
HYPERVISOR_CALL(get_virtual_uart_param, 2, 1, 165)
HYPERVISOR_CALL(configure_virtual_uart_irq, 1, 1, 166)
HYPERVISOR_CALL(open_device, 3, 0, 170)
HYPERVISOR_CALL(close_device, 2, 0, 171)
HYPERVISOR_CALL(map_device_mmio_region, 5, 1, 172)
HYPERVISOR_CALL(unmap_device_mmio_region, 3, 0, 173)
HYPERVISOR_CALL(allocate_device_dma_region, 5, 1, 174)
HYPERVISOR_CALL(free_device_dma_region, 3, 0, 175)
HYPERVISOR_CALL(map_device_dma_region, 6, 0, 176)
HYPERVISOR_CALL(unmap_device_dma_region, 4, 0, 177)
HYPERVISOR_CALL(read_pci_config, 6, 1, 178)
HYPERVISOR_CALL(write_pci_config, 7, 0, 179)
HYPERVISOR_CALL(read_pci_io, 4, 1, 180)
HYPERVISOR_CALL(write_pci_io, 5, 0, 181)
HYPERVISOR_CALL(net_add_multicast_address, 4, 0, 185)
HYPERVISOR_CALL(net_remove_multicast_address, 4, 0, 186)
HYPERVISOR_CALL(net_start_tx_dma, 4, 0, 187)
HYPERVISOR_CALL(net_stop_tx_dma, 3, 0, 188)
HYPERVISOR_CALL(net_start_rx_dma, 4, 0, 189)
HYPERVISOR_CALL(net_stop_rx_dma, 3, 0, 190)
HYPERVISOR_CALL(net_set_interrupt_status_indicator, 4, 0, 191)
HYPERVISOR_CALL(net_set_interrupt_mask, 4, 0, 193)
HYPERVISOR_CALL(net_control, 6, 2, 194)
HYPERVISOR_CALL(connect_interrupt_event_receive_port, 4, 0, 197)
HYPERVISOR_CALL(disconnect_interrupt_event_receive_port, 4, 0, 198)
HYPERVISOR_CALL(get_spu_all_interrupt_statuses, 1, 1, 199)
HYPERVISOR_CALL(deconfigure_virtual_uart_irq, 0, 0, 202)
HYPERVISOR_CALL(enable_logical_spu, 2, 0, 207)
HYPERVISOR_CALL(gpu_open, 1, 0, 210)
HYPERVISOR_CALL(gpu_close, 0, 0, 211)
HYPERVISOR_CALL(gpu_device_map, 1, 2, 212)
HYPERVISOR_CALL(gpu_device_unmap, 1, 0, 213)
HYPERVISOR_CALL(gpu_memory_allocate, 5, 2, 214)
HYPERVISOR_CALL(gpu_memory_free, 1, 0, 216)
HYPERVISOR_CALL(gpu_context_allocate, 2, 5, 217)
HYPERVISOR_CALL(gpu_context_free, 1, 0, 218)
HYPERVISOR_CALL(gpu_context_iomap, 5, 0, 221)
HYPERVISOR_CALL(gpu_context_attribute, 6, 0, 225)
HYPERVISOR_CALL(gpu_context_intr, 1, 1, 227)
HYPERVISOR_CALL(gpu_attribute, 5, 0, 228)
HYPERVISOR_CALL(get_rtc, 0, 2, 232)
HYPERVISOR_CALL(set_ppu_periodic_tracer_frequency, 1, 0, 240)
HYPERVISOR_CALL(start_ppu_periodic_tracer, 5, 0, 241)
HYPERVISOR_CALL(stop_ppu_periodic_tracer, 1, 1, 242)
HYPERVISOR_CALL(storage_read, 6, 1, 245)
HYPERVISOR_CALL(storage_write, 6, 1, 246)
HYPERVISOR_CALL(storage_send_device_command, 6, 1, 248)
HYPERVISOR_CALL(storage_get_async_status, 1, 2, 249)
HYPERVISOR_CALL(storage_check_async_status, 2, 1, 254)
HYPERVISOR_CALL(panic, 1, 0, 255)

HYPERVISOR_CALL(construct_lpm, 6, 3, 140)
HYPERVISOR_CALL(destruct_lpm, 1, 0, 141)
HYPERVISOR_CALL(start_lpm, 1, 0, 142)
HYPERVISOR_CALL(stop_lpm, 1, 1, 143)
HYPERVISOR_CALL(copy_lpm_trace_buffer, 3, 1, 144)
HYPERVISOR_CALL(add_lpm_event_bookmark, 5, 0, 145)
HYPERVISOR_CALL(delete_lpm_event_bookmark, 3, 0, 146)
HYPERVISOR_CALL(set_lpm_interrupt_mask, 3, 1, 147)
HYPERVISOR_CALL(get_lpm_interrupt_status, 1, 1, 148)
HYPERVISOR_CALL(set_lpm_general_control, 5, 2, 149)
HYPERVISOR_CALL(set_lpm_interval, 3, 1, 150)
HYPERVISOR_CALL(set_lpm_trigger_control, 3, 1, 151)
HYPERVISOR_CALL(set_lpm_counter_control, 4, 1, 152)
HYPERVISOR_CALL(set_lpm_group_control, 3, 1, 153)
HYPERVISOR_CALL(set_lpm_debug_bus_control, 3, 1, 154)
HYPERVISOR_CALL(set_lpm_counter, 5, 2, 155)
HYPERVISOR_CALL(set_lpm_signal, 7, 0, 156)
HYPERVISOR_CALL(set_lpm_spr_trigger, 2, 0, 157)

#endif
