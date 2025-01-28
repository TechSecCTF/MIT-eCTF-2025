# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

MXC_OPTIMIZE_CFLAGS = -Og -g
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

PROJ_CFLAGS += -Og -g

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
IPATH+=/secrets
VPATH+=src/

VPATH+=wolfssl/wolfcrypt/src/
IPATH+=wolfssl/

# Enable ChaCha20Poly1305 in wolfSSL
# PROJ_CFLAGS += -DHAVE_CHACHA
# PROJ_CFLAGS += -DHAVE_POLY1305a

# Enable AesGcm in wolfSSL
PROJ_CFLAGS += -DHAVE_AESGCM

# stuff we get from enabling crypto_example=1
PROJ_CFLAGS += -DMXC_ASSERT_ENABLE
PROJ_CFLAGS += -DNO_WOLFSSL_DIR
PROJ_CFLAGS += -DWOLFSSL_AES_DIRECT
PROJ_CFLAGS += -DSINGLE_THREADED
# From https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
PROJ_CFLAGS += -DHAVE_PK_CALLBACKS                                                               
PROJ_CFLAGS += -DWOLFSSL_USER_IO                                                                 
PROJ_CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT     

# wolfSSL hardening
# PROJ_CFLAGS += -DTFM_TIMING_RESISTANT
# PROJ_CFLAGS += -DECC_TIMING_RESISTANT
# PROJ_CFLAGS += -DWC_RSA_BLINDING


# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
CRYPTO_EXAMPLE=0

# Enable Crypto Example
#CRYPTO_EXAMPLE=1
