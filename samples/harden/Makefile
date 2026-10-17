# SPDX-License-Identifier: GPL-2.0
#
# Buggy-on-purpose demo drivers for the KCOV/KASAN hardening tutorial.
# Built only as loadable modules (a KASAN report panics the VM, so you
# insmod/rmmod and reboot vng between findings).

obj-$(CONFIG_SAMPLE_HARDEN) += harden_local.o
obj-$(CONFIG_SAMPLE_HARDEN) += harden_remote.o
obj-$(CONFIG_SAMPLE_HARDEN) += harden_ledger.o

harden_local-y  := local.o
harden_remote-y := remote.o
harden_ledger-y := ledger.o
