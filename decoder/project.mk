# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# **********************************************************

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ********** Integration with native KDF code **********
PROJ_CFLAGS += -I./cryptosystem/src
SRCS += ./cryptosystem/src/cryptosystem.c

# ********************** wolfSSL ***********************
VPATH += $(WOLFSSL_PATH)/wolfcrypt/src
IPATH += $(WOLFSSL_PATH)

# Include our necessary features
PROJ_CFLAGS += -DHAVE_AESGCM
PROJ_CFLAGS += -DHAVE_ED25519
PROJ_CFLAGS += -DWOLFSSL_SHA512

# Basics
PROJ_CFLAGS += -DMXC_ASSERT_ENABLE
PROJ_CFLAGS += -DWOLFSSL_NO_OPTIONS_H
PROJ_CFLAGS += -DNO_WOLFSSL_DIR
PROJ_CFLAGS += -DWOLFSSL_AES_DIRECT
PROJ_CFLAGS += -DSINGLE_THREADED
# From https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
PROJ_CFLAGS += -DHAVE_PK_CALLBACKS
PROJ_CFLAGS += -DWOLFSSL_USER_IO
PROJ_CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT

# Hardening
PROJ_CFLAGS += -DTFM_TIMING_RESISTANT
PROJ_CFLAGS += -DECC_TIMING_RESISTANT
PROJ_CFLAGS += -DWC_RSA_BLINDING

# **************** Secrets for Decoder ****************
gen-decoder-secrets:
	python3 gen_decoder_secrets.py $(DECODER_ID)
	# Re-evaluate dependency graph and source tree
	@$(MAKE) --no-print-directory

release: gen-decoder-secrets
