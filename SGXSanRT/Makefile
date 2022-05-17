SGX_SDK ?= /opt/intel/sgxsdk
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
EName ?= "enclave.signed.so"

# current only support x64 arch
SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Werror -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## SGXSanRT App Settings ########

SGXSanRTApp_Cpp_Files := $(wildcard SGXSanRTApp/*.cpp)
SGXSanRTApp_Include_Paths := -ISGXSanRTApp -ISGXSanRTCommon -I../SGXSanManifest -I$(SGX_SDK)/include

SGXSanRTApp_C_Flags := -fPIC $(SGXSanRTApp_Include_Paths) -DENCLAVE_FILENAME="${EName}"

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        SGXSanRTApp_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        SGXSanRTApp_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        SGXSanRTApp_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

SGXSanRTApp_Cpp_Flags := $(SGXSanRTApp_C_Flags)

SGXSanRTApp_Cpp_Objects := $(SGXSanRTApp_Cpp_Files:.cpp=.o)

LibSGXSanRTApp := libSGXSanRTApp.a

######## SGXSanRT Enclave Settings ########

SGXSanRTEnclave_Cpp_Files := $(wildcard SGXSanRTEnclave/*.cpp)
SGXSanRTEnclave_Include_Paths := -ISGXSanRTEnclave -ISGXSanRTCommon -I../SGXSanManifest -I$(SGX_SDK)/include  -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

SGXSanRTEnclave_C_Flags := $(SGXSanRTEnclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS)
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	SGXSanRTEnclave_C_Flags += -fstack-protector
else
	SGXSanRTEnclave_C_Flags += -fstack-protector-strong
endif

SGXSanRTEnclave_Cpp_Flags := $(SGXSanRTEnclave_C_Flags) -nostdinc++

SGXSanRTEnclave_Cpp_Objects := $(sort $(SGXSanRTEnclave_Cpp_Files:.cpp=.o))

LibSGXSanRTEnclave := libSGXSanRTEnclave.a

.PHONY: all
all: $(LibSGXSanRTApp) $(LibSGXSanRTEnclave)
	@rm -f ../output/SGXSanRTEnclave.edl
	@ln -s ../SGXSanRT/SGXSanRTEnclave/SGXSanRTEnclave.edl ../output/SGXSanRTEnclave.edl

######## SGXSanRT App Objects ########

# SGXSanRTApp/SGXSanRTEnclave_u.h: $(SGX_EDGER8R) SGXSanRTEnclave/SGXSanRTEnclave.edl
# 	cd SGXSanRTApp && $(SGX_EDGER8R) --untrusted ../SGXSanRTEnclave/SGXSanRTEnclave.edl --search-path ../SGXSanRTEnclave --search-path $(SGX_SDK)/include
# 	@echo "GEN  =>  $@"

# SGXSanRTApp/SGXSanRTEnclave_u.c: SGXSanRTApp/SGXSanRTEnclave_u.h

# SGXSanRTApp/SGXSanRTEnclave_u.o: SGXSanRTApp/SGXSanRTEnclave_u.c
# 	@$(CC) $(SGX_COMMON_CFLAGS) $(SGXSanRTApp_C_Flags) -c $< -o $@
# 	@echo "CC   <=  $<"

SGXSanRTApp/%.o: SGXSanRTApp/%.cpp ../SGXSanManifest/SGXSanManifest.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(SGXSanRTApp_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(LibSGXSanRTApp): $(SGXSanRTApp_Cpp_Objects)
	@$(AR) rcs $@ $^
	@cp $(LibSGXSanRTApp) ../output/$(LibSGXSanRTApp)

######## SGXSanRT Enclave Objects ########

# SGXSanRTEnclave/SGXSanRTEnclave_t.h: $(SGX_EDGER8R) SGXSanRTEnclave/SGXSanRTEnclave.edl
# 	@cd SGXSanRTEnclave && $(SGX_EDGER8R) --trusted SGXSanRTEnclave.edl --search-path ../SGXSanRTEnclave --search-path $(SGX_SDK)/include
# 	@echo "GEN  =>  $@"

# SGXSanRTEnclave/SGXSanRTEnclave_t.c: SGXSanRTEnclave/SGXSanRTEnclave_t.h

# SGXSanRTEnclave/SGXSanRTEnclave_t.o: SGXSanRTEnclave/SGXSanRTEnclave_t.c
# 	@$(CC) $(SGX_COMMON_CFLAGS) $(SGXSanRTEnclave_C_Flags) -c $< -o $@
# 	@echo "CC   <=  $<"

SGXSanRTEnclave/%.o: SGXSanRTEnclave/%.cpp ../SGXSanManifest/SGXSanManifest.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(SGXSanRTEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(LibSGXSanRTEnclave): $(SGXSanRTEnclave_Cpp_Objects)
	@$(AR) rcs $@ $^
	@cp $(LibSGXSanRTEnclave) ../output/$(LibSGXSanRTEnclave)

.PHONY: clean
clean:
	@rm -f $(LibSGXSanRTApp) $(SGXSanRTApp_Cpp_Objects) $(LibSGXSanRTEnclave) $(SGXSanRTEnclave_Cpp_Objects)
	@rm -f ../output/$(LibSGXSanRTEnclave) ../output/$(LibSGXSanRTApp) ../output/SGXSanRTEnclave.edl