# This file can be used to set build configuration
# variables. These variables are defined in a file called
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# Example: uncomment for debug-friendly optimization
#MXC_OPTIMIZE_CFLAGS = -Og

# Este ejemplo es sólo para la FTHR board:
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
CRYPTO_EXAMPLE=0   # Ponlo a 1 si quieres las funciones de crypto de ejemplo

# ****************** DECODER_ID: lo pasamos al compilar con -e DECODER_ID=0x... ***
ifndef DECODER_ID
$(error DECODER_ID is not set. Must be passed in docker run -e DECODER_ID=0x...)
endif

CFLAGS += -DDECODER_ID=$(DECODER_ID)

# ****************** Incluir paths Maxim SDK (ajusta a tu entorno si difiere) ****
IPATH += $(CMSIS_ROOT)/Device/Maxim/MAX78000/Include
IPATH += $(PERIPH_DRIVER_ROOT)/Include
IPATH += $(BOARD_DIR)/Include
