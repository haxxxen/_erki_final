#include "payload.h"
#include "hvcall.h"
#include "mm.h"
#include "types.h"
#include "common.h"

#include <sys/memory.h>
#include <sys/paths.h>
#include <sys/process.h>
#include <sys/return_code.h>

#include <cell/sysmodule.h>
#include <cell/cell_fs.h>

#include <sysutil/sysutil_common.h>
#include <sysutil/sysutil_sysparam.h>
#include <sysutil/sysutil_game_common.h>
#include <sysutil/sysutil_gamecontent.h>

#define EID_ROOT_KEY_FILE_NAME "erk"

static uint8_t eid_root_key[EID_ROOT_KEY_SIZE];

static float c_firmware=0.0f;
static u8 dex_mode=0;
u64 TOC_OFFSET = TOC_OFFSET_355;
u64 SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_355;

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

static int make_patches(void)
{
	/******************* LV1 Patches *******************/
/* 	// static 4.21 //
	// allow mapping of HTAB with write protection //
	lv1_poke64(0x2DD244, 0x60000000E97F00A8ULL);

	// allow mapping of any needed memory area //
	lv1_poke64(0x2DCA8C, 0x6000000048000028ULL);
	lv1_poke64(0x2DCDBC, 0x392000014BFFFBFDULL);

	// allow setting all bits of SPE register MFC_SR1 //
	lv1_poke64(0x2F99F0, 0x3920FFFFE9430000ULL);

	// change region size for lv2 hmac hash calculation //
	lv1_poke64(0x370AA8, 0x0000000000000001ULL);
	lv1_poke64(0x370AB0, 0xE0D251B556C59F05ULL);
	lv1_poke64(0x370AB8, 0xC232FCAD552C80D7ULL);
	lv1_poke64(0x370AC0, 0x65140CD200000000ULL); */
 	// dynamic //
	u64 lv1_htab=0x2DD244;
	u64 lv1_mmap=0x2DCA8C;
	// u64 lv1_mmap=0x2DCA84;
	u64 lv1_spe=0x2F99F0;
	// allow mapping of HTAB with write protection //
	if(lv1_peek64(lv1_htab)!=0x41DA0054E97F00A8ULL)
	{
		lv1_htab=0;
		for(u64 addr=0x2DD244; addr<0x800000ULL; addr+=4)
		{
			lv1_htab=addr;
			if(lv1_peek64(addr) == 0x41DA0054E97F00A8ULL)
			{
				lv1_htab=addr;
				break;
			}
		}
	}
	if(lv1_htab && lv1_peek64(lv1_htab)==0x41DA0054E97F00A8ULL)
	{
		lv1_poke64(lv1_htab +  0, 0x60000000E97F00A8ULL);
	}

	// allow mapping of any needed memory area //
/* 	if(lv1_peek64(lv1_mmap)!=0x881F00995400063EULL)
	{
		if(lv1_peek64(lv1_mmap + 4)!=0x6000000048000028ULL)
		{
			lv1_mmap=0;
			for(u64 addr=0x2DCA84; addr<0x800000ULL; addr+=4)
			{
				lv1_mmap=addr;
				if(lv1_peek64(addr) == 0x881F00995400063EULL)
				{
					lv1_mmap=addr+8;
					break;
				}
			}
		}
	} */
	if(lv1_peek64(lv1_mmap)!=0x6000000048000028ULL)
	{
		lv1_mmap=0;
		for(u64 addr=0x2DCA8C; addr<0x800000ULL; addr+=4)
		{
			lv1_mmap=addr;
			if(lv1_peek64(addr) == 0x881F00995400063EULL)
			{
				lv1_mmap=addr+8;
				break;
			}
		}
	}
	if(lv1_mmap && lv1_peek64(lv1_mmap)!=0x6000000048000028ULL)
	{
		lv1_poke64(lv1_mmap +   0, 0x6000000048000028ULL);
		lv1_poke64(lv1_mmap + 816, 0x392000014BFFFBFDULL);
	}

	// allow setting all bits of SPE register MFC_SR1 //
	if(lv1_peek64(lv1_spe)!=0x39200009E9430000ULL)
	{
		lv1_spe=0;
		for(u64 addr=0x2F99F0; addr<0x800000ULL; addr+=4)
		{
			lv1_spe=addr;
			if(lv1_peek64(addr) == 0x39200009E9430000ULL)
			{
				lv1_spe=addr;
				break;
			}
		}
	}
	if(lv1_spe && lv1_peek64(lv1_spe)==0x39200009E9430000ULL)
	{
		lv1_poke64(lv1_spe +  0, 0x3920FFFFE9430000ULL);
	}

	/******************* LV2 Patches *******************/
	/* permission patch */
	lv2_poke64(0x8000000000003D90ULL, 0x386000014E800020ULL);

	/* remove page protection bits from htab entries */
	patch_htab_entries(0);

	return 0;
}

static int dump_eid_root_key(const char* file_path) {
	int result;

	FILE* fp;
	int poke_installed;
	int payload_installed;

	poke_installed = 0;
	payload_installed = 0;

	// not needed for CFW's //
	console_printf("install_new_poke() not needed!\n");
	// result = install_new_poke();
	result = 0;
	if (result != 0) {
		console_printf("install_new_poke() failed: 0x%08X\n", result);
		goto error;
	}
	else
		// poke_installed = 1;
		poke_installed = 0;

	detect_firmware();
	console_printf("make_patches()\n");
	result = make_patches();
	if (result != 0) {
		console_printf("make_patches() failed: 0x%08X\n", result);
		goto error;
	}

	console_printf("install_payload()\n");
	result = install_payload();
	if (result != 0) {
		console_printf("install_payload() failed: 0x%08X\n", result);
		goto error;
	}
	payload_installed = 1;

	memset(eid_root_key, 0, EID_ROOT_KEY_SIZE);

	console_printf("run_payload()\n");
	result = run_payload((uintptr_t)eid_root_key, EID_ROOT_KEY_SIZE);
	if (result != 0) {
		console_printf("run_payload() failed: 0x%08X\n", result);
		goto error;
	}

	console_printf("fopen()\n");
	fp = fopen(file_path, "wb");
	if (!fp) {
		result = errno;
		console_printf("fopen() failed: 0x%08X\n", result);
		goto error;
	}

	console_printf("fwrite()\n");
	fwrite(eid_root_key, 1, EID_ROOT_KEY_SIZE, fp);

	console_printf("fclose()\n");
	fclose(fp);

	result = 0;

error:
	if (payload_installed) {
		console_printf("remove_payload()\n");
		result = remove_payload();
		if (result != 0)
			console_printf("remove_payload() failed: 0x%08X\n", result);
	}

	if (poke_installed) {
		console_printf("remove_new_poke()\n");
		result = remove_new_poke();
		if (result != 0)
			console_printf("remove_new_poke() failed: 0x%08X\n", result);
	}

	return result;
}

SYS_PROCESS_PARAM(1001, 0x10000)

int main(void) {
	int result;

	char dump_file_path[CELL_GAME_PATH_MAX];
	char content_info_path[CELL_GAME_PATH_MAX];
	char usrdir_path[CELL_GAME_PATH_MAX];
	unsigned int type, attributes;
	int dumped;

	dumped = 0;

	result = cellSysmoduleLoadModule(CELL_SYSMODULE_IO);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleLoadModule(CELL_SYSMODULE_IO) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleLoadModule(CELL_SYSMODULE_FS) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellSysmoduleLoadModule(CELL_SYSMODULE_SYSUTIL);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleLoadModule(CELL_SYSMODULE_SYSUTIL) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellSysmoduleLoadModule(CELL_SYSMODULE_SYSUTIL_GAME);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleLoadModule(CELL_SYSMODULE_SYSUTIL_GAME) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellGameBootCheck(&type, &attributes, NULL, NULL);
	if (result != CELL_OK) {
		console_printf("cellGameBootCheck() failed: 0x%08X\n", result);
		goto error;
	}

	if (type == CELL_GAME_GAMETYPE_HDD) {
		result = cellGameContentPermit(content_info_path, usrdir_path);
		if (result != CELL_OK) {
			console_printf("cellGameContentPermit() failed: 0x%08X\n", result);
			goto error;
		}

		detect_firmware();
		if (c_firmware==3.55f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_355D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_355D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_355;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_355;
			}
		}
		if (c_firmware==4.21f) {
			if (!dex_mode) {
				TOC_OFFSET = TOC_OFFSET_421;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_421;
			}
			else
			if (dex_mode==2) {
				TOC_OFFSET = TOC_OFFSET_421D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_421D;
			}
			else
			if (dex_mode==1) {
				TOC_OFFSET = TOC_OFFSET_421E;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_421E;
			}
		}
/* 		if (c_firmware==4.30f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_430D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_430D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_430;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_430;
			}
		} */
		if (c_firmware==4.46f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_446D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_446D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_446;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_446;
			}
		}
/* 		if (c_firmware==4.65f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_465D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_465D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_465;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_465;
			}
		}
		if (c_firmware==4.70f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_470D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_470D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_470;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_470;
			}
		}
		if (c_firmware==4.75f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_475D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_475;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475;
			}
		}
		if (c_firmware==4.76f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_475D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_475;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475;
			}
		} */
		if (c_firmware==4.78f) {
			if (dex_mode) {
				TOC_OFFSET = TOC_OFFSET_475D;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475D;
			}
			else {
				TOC_OFFSET = TOC_OFFSET_475;
				SYSCALL_TABLE_OFFSET = SYSCALL_TABLE_OFFSET_475;
			}
		}

		// snprintf(dump_file_path, sizeof(dump_file_path), "%s/%s", usrdir_path, EID_ROOT_KEY_FILE_NAME);
		// snprintf(dump_file_path, sizeof(dump_file_path), "/dev_rebug/rebug/packages/PS3_GAME/USRDIR/%s", EID_ROOT_KEY_FILE_NAME);
		snprintf(dump_file_path, sizeof(dump_file_path), "/dev_flash2/%s", EID_ROOT_KEY_FILE_NAME);
		dumped = dump_eid_root_key(dump_file_path) == 0;
		console_printf("Dump file path: %s\n", dump_file_path);
	} else {
		console_printf("Error! The application type is not a HDD boot game!\n");
	}

	result = cellSysmoduleUnloadModule(CELL_SYSMODULE_SYSUTIL_GAME);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleUnloadModule(CELL_SYSMODULE_SYSUTIL_GAME) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellSysmoduleUnloadModule(CELL_SYSMODULE_SYSUTIL);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleUnloadModule(CELL_SYSMODULE_SYSUTIL) failed: 0x%08X\n", result);
		goto error;
	}

	if (dumped) {
		console_printf("cellFsUnlink()\n");
		cellFsUnlink("/dev_hdd0/tmp/turnoff");

		console_printf("triple_beep()\n");
		triple_beep();
	}

	result = cellSysmoduleUnloadModule(CELL_SYSMODULE_FS);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleUnloadModule(CELL_SYSMODULE_FS) failed: 0x%08X\n", result);
		goto error;
	}

	result = cellSysmoduleUnloadModule(CELL_SYSMODULE_IO);
	if (result != CELL_OK) {
		console_printf("cellSysmoduleUnloadModule(CELL_SYSMODULE_IO) failed: 0x%08X\n", result);
		goto error;
	}

	if (dumped) {
		console_printf("reboot()\n");
		// reboot();
		hard_reboot();
	}

	result = 0;

error:
	sys_process_exit(result);

	return result;
}
