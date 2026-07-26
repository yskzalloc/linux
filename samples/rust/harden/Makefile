# SPDX-License-Identifier: GPL-2.0
#
# Rust hardening demo drivers:
#   local.rs  -> local.ko   (LOCAL KCOV coverage)   CONFIG_SAMPLE_RUST_HARDEN
#   remote.rs -> remote.ko  (REMOTE KCOV coverage)  CONFIG_SAMPLE_RUST_HARDEN_REMOTE
#
# remote.rs uses the KCOV remote FFI, exposed to Rust because
# rust/bindings/bindings_helper.h now includes <linux/kcov.h>. The REMOTE
# config defaults to the value of SAMPLE_RUST_HARDEN, so both build together.
#
# Rust modules are single-object: the .ko name comes from the source basename;
# the /dev node name comes from module! + MiscDeviceOptions.

obj-$(CONFIG_SAMPLE_RUST_HARDEN)		+= local.o
obj-$(CONFIG_SAMPLE_RUST_HARDEN_REMOTE)	+= remote.o
