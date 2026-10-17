.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: rust_kworker_remote
============================================

Rust module testing kcov_df_remote_start()/kcov_df_remote_stop() from
kworker context: the trigger queues a work item on system_wq whose three
phases (populate/update/drain of a CompositeStore of RBTrees) run with
remote capture on handle 1, which the runner publishes with
KCOV_DF_REMOTE_ENABLE. Built only with CONFIG_RUST=y::

  ./test_modules.py -t rust_kworker_remote
  ./trigger-view.py rust_kworker_remote --remote

Each phase is a method taking ``&mut self``, which rustc marks
``dereferenceable(24)``, the size of the three RBTree roots, so every
record of ``self`` carries the 24 bytes behind it as well as the pointer.
test_modules.py checks that they are recorded, that the three roots are
NULL when populate() starts and set when update() and drain() do, and,
through DWARF, that the bytes are the three members of CompositeStore::

  rust_kworker_remote.rs:58   <rust_kworker_remote::CompositeStore>::populate+0x2f(self=0xffff8880019f7c20 -> CompositeStore {.primary.root.rb_node=0x0, .aux.root.rb_node=0x0, .scratch.root.rb_node=0x0})
  rust_kworker_remote.rs:73   <rust_kworker_remote::CompositeStore>::update+0x2c(self=0xffff8880019f7c20 -> CompositeStore {.primary.root.rb_node=0xffff888006f68e00, .aux.root.rb_node=0xffff888006f68a00, .scratch.root.rb_node=0xffff888006f68600})
