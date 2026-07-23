all : flash

TARGET := einszeit
TARGET_MCU := CH32V003

ADDITIONAL_C_FILES+=rv003usb/rv003usb.S rv003usb/rv003usb.c
EXTRA_CFLAGS:=-Irv003usb/lib -Irv003usb

include ch32fun/ch32fun.mk

flash : cv_flash
clean : cv_clean

all : flash
