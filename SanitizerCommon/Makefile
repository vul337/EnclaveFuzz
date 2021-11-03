# Customized, I set a default path in my environment, maybe passed by parent makefile
sanitizer_common_path_prefix ?= /home/leone/文档/llvm-project/build/projects/compiler-rt/lib/sanitizer_common/CMakeFiles

sanitizer_common_dirs := RTSanitizerCommon RTSanitizerCommonLibc RTSanitizerCommonCoverage RTSanitizerCommonSymbolizer

arch := x86_64

sanitizer_common_libs := $(foreach sanitizer_common_dir, $(sanitizer_common_dirs), libclang_rt.$(sanitizer_common_dir)-$(arch).a)

.PHONY: all clean
all: $(sanitizer_common_libs)

.SECONDEXPANSION:
$(sanitizer_common_libs): $$(patsubst libclang_rt.%-$(arch).a, $(sanitizer_common_path_prefix)/%.$(arch).dir, $$@)/*.o
	@$(AR) rsc $@ $^
	@echo "AR => $@"

# I don't remove for backup, because we can't guarantee there are compiled sanitizer common objects at anytime
clean:
	@rm -f lib*.a