.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: pointee_access_c
=========================================

C module whose functions load and store through plain C pointer arguments,
for ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS``. Opted in with
``KCOV_DATAFLOW_pointee_access_c.o := y``; writing
``/sys/kernel/debug/kcov_dataflow_test/trigger_access`` runs it::

  ./test_modules.py -t pointee_access_c
  ./trigger-view.py pointee_access_c
  ./trigger-view.py pointee_access_c --raw
  ./trigger-view.py pointee_access_c --accesses=summary

A plain C pointer has no dereferenceable contract, so no pointee snapshot is
recorded for any of these arguments: what the records show of a pointee is
what the function itself loaded or stored, as ACCESS records, made right
after each access when it executed, with the program's own value. Nothing is
read for them. test_modules.py checks, from the values the trigger sets up:

- ``pa_get``: the loads of ``s->in.x`` and ``s->in.y`` (5, 6);
- ``pa_set_tag``: the store of 42 to ``s->tag[2]``;
- ``pa_maybe(s, 0)`` and ``pa_maybe(s, 1)``: only the second call loads,
  and only it has a record;
- ``pa_bump`` and ``pa_twice``: load 100, store 101, then ``pa_twice``'s
  load 101 and store 202, then load 202 and store 203 -- every access to
  the one member, in order, with the value it had then;
- ``pa_locked``: the load of ``s->in.x`` made under the spinlock;
- ``pa_key``: ``container_of()``'s key, 8 bytes *before* the pointer;
- ``pa_once``: ``READ_ONCE()``/``WRITE_ONCE()`` with
  ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS_VOLATILE`` only, and never the
  inline-assembly ``atomic_inc()``;
- ``pa_bits``: the byte holding bit-fields ``flag`` and ``mode``, which the
  DWARF cuts into 5 and 17;
- ``pa_wide``: a 16-byte load as two 8-byte pieces;
- ``pa_depth(s, 2)``: every recursion level's own load, attributed to that
  level's call;
- ``pa_indirect``: the load of ``h->state``, but not of ``h->state->id``,
  which goes through a pointer loaded from memory;
- ``pa_copy``: nothing -- a ``memcpy()`` has no value to record.

Without ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS`` the module records no ACCESS
records, which is checked too. With ``sancov``, each access is also checked
to name the member the DWARF places at its offset (``s->in.x``,
``s->tag[2]``, ``h->state``) and the ``container_of()`` key to lie outside
``struct list_head``.
