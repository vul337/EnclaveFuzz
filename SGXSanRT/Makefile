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

SGXSanRTApp_C_Flags := -fPIC $(SGXSanRTApp_Include_Paths) -DENCLAVE_FILENAME="${EName}" -DOUT_ENCLAVE

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

LibSGXSanRTApp_a := libSGXSanRTApp.a
LibSGXSanRTApp_so := libSGXSanRTApp.so

######## SGXSanRT Enclave Settings ########

SGXSanRTEnclave_Cpp_Files := $(wildcard SGXSanRTEnclave/*.cpp)
SGXSanRTEnclave_Include_Paths := -ISGXSanRTEnclave -ISGXSanRTCommon -I../SGXSanManifest -I$(SGX_SDK)/include  -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

SGXSanRTEnclave_C_Flags := $(SGXSanRTEnclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(MITIGATION_CFLAGS) -DIN_ENCLAVE
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	SGXSanRTEnclave_C_Flags += -fstack-protector
else
	SGXSanRTEnclave_C_Flags += -fstack-protector-strong
endif

SGXSanRTEnclave_Cpp_Flags := $(SGXSanRTEnclave_C_Flags) -nostdinc++

SGXSanRTEnclave_Cpp_Objects := $(sort $(SGXSanRTEnclave_Cpp_Files:.cpp=.o))

LibSGXSanRTEnclave := libSGXSanRTEnclave.a

.PHONY: all LibSGXSanRTApp
all: LibSGXSanRTApp $(LibSGXSanRTEnclave)

######## SGXSanRT App Objects ########

SGXSanRTApp/%.o: SGXSanRTApp/%.cpp ../SGXSanManifest/SGXSanManifest.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(SGXSanRTApp_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

LibSGXSanRTApp: $(LibSGXSanRTApp_a) $(LibSGXSanRTApp_so)

$(LibSGXSanRTApp_a): $(SGXSanRTApp_Cpp_Objects)
	@$(AR) rcs $@ $^
	@echo "AR   =>  $@"

$(LibSGXSanRTApp_so): $(SGXSanRTApp_Cpp_Objects)
	@$(CXX) -shared $^ -o $@
	@echo "CXX  =>  $@"

######## SGXSanRT Enclave Objects ########

SGXSanRTEnclave/%.o: SGXSanRTEnclave/%.cpp ../SGXSanManifest/SGXSanManifest.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(SGXSanRTEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(LibSGXSanRTEnclave): $(SGXSanRTEnclave_Cpp_Objects)
	@$(AR) rcs $@ $^
	@echo "AR   =>  $@"

.PHONY: clean
clean:
	@rm -f $(LibSGXSanRTApp_a) $(LibSGXSanRTApp_so) $(SGXSanRTApp_Cpp_Objects) $(LibSGXSanRTEnclave) $(SGXSanRTEnclave_Cpp_Objects)
