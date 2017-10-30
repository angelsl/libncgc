ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif
include $(DEVKITARM)/base_tools

ARCH		:=	-marm
ARCHFLAGS	:=	-march=armv5te -mtune=arm946e-s \
				-fomit-frame-pointer -ffunction-sections -fdata-sections -ffast-math \
				-DARM9

CFLAGS		:=	$(CFLAGS) $(ARCH) $(ARCHFLAGS)
CXXFLAGS	:=	$(CXXFLAGS) $(ARCH) $(ARCHFLAGS)
ASFLAGS		:=	$(ASFLAGS) -g $(ARCH)

CFILES		:=	$(CFILES) src/platform/ntr.c