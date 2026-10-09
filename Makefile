ARCH ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/x86/')
BUILD := build

all: $(BUILD)/guard.bpf.o

$(BUILD)/vmlinux.h:
	@mkdir -p $(BUILD)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/guard.tmp.o: bpf/guard.bpf.c $(BUILD)/vmlinux.h
	clang -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -I$(BUILD) -c $< -o $@

$(BUILD)/guard.bpf.o: $(BUILD)/guard.tmp.o
	bpftool gen object $@ $<

clean:
	rm -rf $(BUILD)

.PHONY: all clean
