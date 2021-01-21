CELL_MK_DIR ?= $(CELL_SDK)/samples/mk

include $(CELL_MK_DIR)/sdk.makedef.mk

PPU_SRCS = main.c mm.c hvcall.c payload.c util.c
PPU_TARGET = erk_dumper.elf
SCEDATA = f:/bkp/tools/

#PPU_CFLAGS += -g -D_DEBUG
#PPU_LDFLAGS +=

PPU_LDLIBS = -lm -lio_stub -lfs_stub -lsysmodule_stub -lsysutil_stub -lsysutil_game_stub

include $(CELL_MK_DIR)/sdk.target.mk

CLEANFILES = $(PPU_TARGET)

all: $(PPU_TARGET)
	# $(SCEDATA)scetool --data-path $(SCEDATA)data --verbose --sce-type=SELF --key-revision=01 --self-auth-id=1010000001000003 --self-vendor-id=01000002 --self-type=NPDRM --self-fw-version=0003004000000000 --self-app-version=0001000000000000 --self-ctrl-flags=4000000000000000000000000000000000000000000000000000000000000002 --self-cap-flags=00000000000000000000000000000000000000000000003B0000000100002000 --np-license-type=FREE --np-app-type=EXEC --np-content-id=UP0001-FLTZ00010_00-ERKDUMPER0000000 --np-real-fname=EBOOT.BIN --compress-data=TRUE --encrypt EBOOT.ELF EBOOT.BIN
	$(SCEDATA)scetool --verbose --data-path $(SCEDATA)data --sce-type=SELF --compress-data=TRUE --skip-sections=FALSE --key-revision=01 --self-ctrl-flags=4000000000000000000000000000000000000000000000000000000000000002 --self-auth-id=1010000001000003 --self-app-version=0001000000000000 --self-add-shdrs=TRUE --self-vendor-id=01000002 --self-type=APP --self-fw-version=0003004000000000 --encrypt $(PPU_TARGET) erk_dumper.self
