#include "payload.h"
#include "erk_payload_355C.shellcode.inc"
#include "erk_payload_355D.shellcode.inc"
#include "erk_payload_421C.shellcode.inc"
#include "erk_payload_421D.shellcode.inc"
#include "erk_payload_421E.shellcode.inc"
// #include "erk_payload_430C.shellcode.inc"
// #include "erk_payload_430D.shellcode.inc"
#include "erk_payload_446C.shellcode.inc"
#include "erk_payload_446D.shellcode.inc"
// #include "erk_payload_465C.shellcode.inc"
// #include "erk_payload_465D.shellcode.inc"
// #include "erk_payload_470C.shellcode.inc"
// #include "erk_payload_470D.shellcode.inc"
#include "erk_payload_475C.shellcode.inc"
#include "erk_payload_475D.shellcode.inc"
// #include "erk_payload_476C.shellcode.inc"
// #include "erk_payload_476D.shellcode.inc"
// #include "erk_payload_478C.shellcode.inc"
// #include "erk_payload_478D.shellcode.inc"
#include "types.h"

static uint64_t real_opd_offset = 0;
static u8 dex_mode=0;
// static int deh_mode;
static float c_firmware=0.0f;

static void detect_firmware(void) {
	u64 CEX=0x4345580000000000ULL;
	u64 DEX=0x4445580000000000ULL;
	u64 DEH=0x4445480000000000ULL;

	dex_mode=0;

	if(lv2_peek64(0x80000000002D83D0ULL)==CEX) { dex_mode=0; c_firmware=3.55f; } else
	if(lv2_peek64(0x80000000002EFE20ULL)==DEX) { dex_mode=2; c_firmware=3.55f; }

	if(lv2_peek64(0x80000000002E8610ULL)==CEX) { dex_mode=0; c_firmware=4.21f; } else
	if(lv2_peek64(0x8000000000302D88ULL)==DEX) { dex_mode=2; c_firmware=4.21f; }
	if(lv2_peek64(0x800000000032B348ULL)==DEH) { dex_mode=1; c_firmware=4.21f; }

	// if(lv2_peek64(0x80000000002E9F08ULL)==CEX) { dex_mode=0; c_firmware=4.30f; } else
	// if(lv2_peek64(0x8000000000304630ULL)==DEX) { dex_mode=2; c_firmware=4.30f; }

	if(lv2_peek64(0x80000000002EA9A8ULL)==CEX) { dex_mode=0; c_firmware=4.46f; } else
	if(lv2_peek64(0x8000000000305400ULL)==DEX) { dex_mode=2; c_firmware=4.46f; }

	// if(lv2_peek64(0x80000000002ED860ULL)==CEX) { dex_mode=0; c_firmware=4.65f; } else
	// if(lv2_peek64(0x800000000030F1A8ULL)==DEX) { dex_mode=2; c_firmware=4.65f; }

	// if(lv2_peek64(0x80000000002ED778ULL)==CEX) { dex_mode=0; c_firmware=4.70f; } else
	// if(lv2_peek64(0x800000000030F240ULL)==DEX) { dex_mode=2; c_firmware=4.70f; }

	// if(lv2_peek64(0x80000000002ED818ULL)==CEX) { if(lv2_peek64(0x80000000002FCB68ULL)==(0x323031352F30342FULL)) { dex_mode=0; c_firmware=4.75f; } } else
	// if(lv2_peek64(0x800000000030F2D0ULL)==DEX) { if(lv2_peek64(0x800000000031EF48ULL)==(0x323031352F30342FULL)) { dex_mode=2; c_firmware=4.75f; } }

	// if(lv2_peek64(0x80000000002ED818ULL)==CEX) { if(lv2_peek64(0x80000000002FCB68ULL)==(0x323031352F30382FULL)) { dex_mode=0; c_firmware=4.76f; } } else
	// if(lv2_peek64(0x800000000030F2D0ULL)==DEX) { if(lv2_peek64(0x800000000031EF48ULL)==(0x323031352F30382FULL)) { dex_mode=2; c_firmware=4.76f; } }

	if(lv2_peek64(0x80000000002ED818ULL)==CEX) { if(lv2_peek64(0x80000000002FCB68ULL)==(0x323031352F31322FULL)) { dex_mode=0; c_firmware=4.78f; } } else
	if(lv2_peek64(0x800000000030F2D0ULL)==DEX) { if(lv2_peek64(0x800000000031EF48ULL)==(0x323031352F31322FULL)) { dex_mode=2; c_firmware=4.78f; } }
}

int install_payload(void) {
	detect_firmware();
	if (c_firmware==3.55f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_355D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_355D;
			if (erk_payload_355D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_355D, PAYLOAD_OFFSET, erk_payload_355D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_355D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_355;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_355;
			if (erk_payload_355C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_355C, PAYLOAD_OFFSET, erk_payload_355C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_355);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
	if (c_firmware==4.21f) {
		if (!dex_mode) {
			TOC_OFFSET=TOC_OFFSET_421;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_421;
			if (erk_payload_421C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_421C, PAYLOAD_OFFSET, erk_payload_421C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_421);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else
		if (dex_mode==2) {
			TOC_OFFSET=TOC_OFFSET_421D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_421D;
			if (erk_payload_421D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_421D, PAYLOAD_OFFSET, erk_payload_421D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_421D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else
		if (dex_mode==1) {
			TOC_OFFSET=TOC_OFFSET_421E;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_421E;
			if (erk_payload_421E_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_421E, PAYLOAD_OFFSET, erk_payload_421E_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_421E);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
/* 	if (c_firmware==4.30f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_430D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_430D;
			if (erk_payload_430D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_430D, PAYLOAD_OFFSET, erk_payload_430D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_430D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_430;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_430;
			if (erk_payload_430C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_430C, PAYLOAD_OFFSET, erk_payload_430C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_430);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	} */
	if (c_firmware==4.46f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_446D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_446D;
			if (erk_payload_446D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_446D, PAYLOAD_OFFSET, erk_payload_446D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_446D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_446;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_446;
			if (erk_payload_446C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_446C, PAYLOAD_OFFSET, erk_payload_446C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_446);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
/* 	if (c_firmware==4.65f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_465D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_465D;
			if (erk_payload_465D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_465D, PAYLOAD_OFFSET, erk_payload_465D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_465D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_465;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_465;
			if (erk_payload_465C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_465C, PAYLOAD_OFFSET, erk_payload_465C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_465);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
	if (c_firmware==4.70f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_470D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_470D;
			if (erk_payload_470D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_470D, PAYLOAD_OFFSET, erk_payload_470D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_470D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_470;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_470;
			if (erk_payload_470C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_470C, PAYLOAD_OFFSET, erk_payload_470C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_470);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
	if (c_firmware==4.75f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_475D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475D;
			if (erk_payload_475D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475D, PAYLOAD_OFFSET, erk_payload_475D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_475;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475;
			if (erk_payload_475C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475C, PAYLOAD_OFFSET, erk_payload_475C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}
	if (c_firmware==4.76f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_475D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475D;
			if (erk_payload_475D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475D, PAYLOAD_OFFSET, erk_payload_475D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_475;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475;
			if (erk_payload_475C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475C, PAYLOAD_OFFSET, erk_payload_475C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	} */
	if (c_firmware==4.78f) {
		if (dex_mode) {
			TOC_OFFSET=TOC_OFFSET_475D;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475D;
			if (erk_payload_475D_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475D, PAYLOAD_OFFSET, erk_payload_475D_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475D);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
		else {
			TOC_OFFSET=TOC_OFFSET_475;
			SYSCALL_TABLE_OFFSET=SYSCALL_TABLE_OFFSET_475;
			if (erk_payload_475C_size <= 0) return -1;
			lv2_copy_from_user(erk_payload_475C, PAYLOAD_OFFSET, erk_payload_475C_size);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 0, PAYLOAD_OFFSET);
			lv2_poke64(PAYLOAD_OPD_OFFSET + 8, TOC_OFFSET_475);
			real_opd_offset = SYSCALL_OPD_OFFSET(SYSCALL_RUN_PAYLOAD);
			lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), PAYLOAD_OPD_OFFSET);
		}
	}

	return 0;
}

int remove_payload(void) {
	if (real_opd_offset != 0) {
		lv2_poke64(SYSCALL_OPD_PTR_OFFSET(SYSCALL_RUN_PAYLOAD), real_opd_offset);
		real_opd_offset = 0;
	}

	return 0;
}
