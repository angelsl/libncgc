export CC	:=	gcc
export CXX	:=	g++

CFILES		:=	$(CFILES) test.c
OBJFILES	:=	$(OBJFILES) obj/$(PLATFORM)/ntr_blowfish.bin.o

ifeq ($(OS),Windows_NT)
    TARGET := out/$(PLATFORM)/test.exe
else
    TARGET := out/$(PLATFORM)/test
endif

.SECONDEXPANSION:
$(TARGET): $$(OBJFILES)
	@if [ $$(sha256sum ntr_blowfish.bin | cut -d ' ' -f 1) != \
		"bedd20bd7f9cac742ad760e2448d4043e0d37121b67a1be3a6b8afbb8a34f08e" ]; then \
		echo "Invalid ntr_blowfish.bin"; \
		exit 1; \
	fi
	@mkdir -p $(dir $@)
	@echo $^ =\> $@
	@$(CC) $^ -o $@

.DEFAULT_GOAL	:=	$(TARGET)