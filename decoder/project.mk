# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

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

# ****************** Crypto Example Flags **************
#VPATH += wolfssl/wolfcrypt/src
#IPATH += wolfssl
# PROJ_CFLAGS += -DMXC_ASSERT_ENABLE
# # eCTF Crypto Example - WolfSSL Flags
# PROJ_CFLAGS += -DNO_WOLFSSL_DIR
# PROJ_CFLAGS += -DWOLFSSL_AES_DIRECT
# PROJ_CFLAGS += -DSINGLE_THREADED
# # From https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
# PROJ_CFLAGS += -DHAVE_PK_CALLBACKS                                                               
# PROJ_CFLAGS += -DWOLFSSL_USER_IO                                                                 
# PROJ_CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT 