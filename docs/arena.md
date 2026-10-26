<!--
 Copyright 2026 Liang Tang.
 SPDX-License-Identifier: Apache-2.0
-->

# BPF arena memory

A [BPF arena](https://docs.kernel.org/bpf/map_arena.html)
(`BPF_MAP_TYPE_ARENA`) is memory shared by BPF programs and user space.
`bpftool map dump` can't show it, as it has no keys or values. bpfsnoop
expressions can read it with the builtin function
`arena(<map>, [<size>, [<offset>]])`:

- `<map>`: the arena map, by ID, e.g. `42`, or by name, e.g. `"my_arena"`. A
  name must match one map; use the ID otherwise.
- `<size>`: the number of bytes, at most 4096. By default, 4096.
- `<offset>`: the offset in the arena. By default, 0.

As a whole expression, `arena()` dumps the bytes with `hex.Dump()`:

```
$ bpfsnoop --read 'arena("arenaprobe", 64)'
Expr: arena("arenaprobe", 64)
Out: (array(u8[64]))'arena("arenaprobe", 64)'=
00000000  01 00 00 00 66 69 72 73  74 00 00 00 00 00 00 00  |....first.......|
00000010  18 70 80 26 94 7f 00 00  02 00 00 00 73 65 63 6f  |.p.&........seco|
00000020  6e 64 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |nd..............|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

The offsets on the left are relative to `<offset>`. To dump more than 4096
bytes, dump with several offsets, e.g. `--read 'arena(42, 4096)' --read
'arena(42, 4096, 4096)'`.

In a larger expression, `arena()` is a `u8[<size>]` array, so it can be
indexed, cast, or passed to `str()`, `hex()` and the like, in `--read`,
`--filter-arg` and `--output-arg`:

```
$ bpfsnoop --read 'str(arena("arenaprobe", 12, 4))'
Out: (array(u8[12]))'str(arena("arenaprobe", 12, 4))'="first"

$ bpfsnoop -t netif_receive_skb --filter-arg 'arena("arenaprobe", 32)[24] == 2' \
    --output-arg '*(int *)arena("arenaprobe", 4, 24)'
```

A BPF program can use only one arena, so all the `--filter-arg` and
`--output-arg` expressions, or one `--read` expression, can use only one arena
map.

## Tracing a bpf prog that uses an arena

When tracing a bpf prog with `-p`, a func param tagged `__arg_arena` points
into the prog's arena. `--output-arg` and `--filter-arg` can read the arena
through such a param, and the output marks its type as `__arena`:

```
$ bpfsnoop -p 'n:arena_main:arena_probe' --output-arg 'n->val' --output-arg 'str(n->name)'
→ arena_probe[bpf] args=((struct arena_node __arena *)n=0x7f9b9b5f2000) ...
Arg attrs: (int)'n->val'=1, (array(char[12]))'str(n->name)'="first"
```

Pointers loaded from the arena are followed too, like `next` in
`n->next->val`. A pointer loaded from the arena may as well be a kernel pointer
stored in the arena, like `task` in `((struct task_struct *)n->task)->comm`,
so each address is translated only if it's in the arena's user range. User
and kernel addresses don't overlap.

Cast a kernel pointer stored in the arena to its kernel type. The program's
BTF describes `struct task_struct` as of the kernel the program was built
against, whose layout may differ from the running kernel's. The cast looks
the type up in the running kernel's BTF.

## How it works

Pointers into an arena hold addresses in the user space mapping of its owner,
which `bpf_probe_read_kernel()` can't read. The kernel maps the arena pages at
its own address too: the page of user address `addr` at
`kern_vm_start + (u32)addr`, where `kern_vm_start` is
`kern_vm->addr + GUARD_SZ/2`.

So the BPF program of bpfsnoop loads the arena map pointer, which is its
`struct bpf_arena`, and reads `user_vm_start` and `kern_vm` from it at run
time. The verifier checks these reads against kernel BTF. Then `arena()` is
the memory at `kern_vm_start + (u32)(user_vm_start + <offset>)`.

For a traced bpf prog, bpfsnoop finds its arena among its maps: a prog uses
one arena at most. Before each read through an `__arg_arena` param, or through
a pointer loaded from the arena, `bpfsnoop_arena_addr()` in
[bpf/bpfsnoop_arena.h](../bpf/bpfsnoop_arena.h) translates the address `addr`
to `kern_vm_start + (u32)addr` the same way if it's in the arena's user range,
`[user_vm_start, user_vm_end)`, and leaves it as it is otherwise.

## Limitations

- An arena needs Linux 6.9 or newer.
- The arena must be mapped to user space, which fixes its user address range.
- If a read touches an arena page that hasn't been allocated, it reads as
  zeros. Reading never allocates pages.
