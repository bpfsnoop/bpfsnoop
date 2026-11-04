# Comparing strings

`--filter-arg`, `--output-arg` and `--read` can compare a string with a string literal through `str()`:

```sh
bpfsnoop -k security_file_open \
  --filter-arg 'str(file->f_path.dentry->d_name.name) == "passwd"'

bpfsnoop -k generic_xdp_install --filter-arg 'str(dev->name) != "lo"'
```

The argument of `str()` must be a char pointer or a char array, including `unsigned char` and `u8`. With a size, `str(x, size)` is a char array of `size` bytes at `x`. Only `==` and `!=` with a string literal are supported. The literal can be on either side, can use escapes like `"\t"`, and is at most 254 bytes. In `--output-arg` and `--read`, the comparison is output as a bool.

The comparison is exact: `str(dev->name) == "lo"` doesn't match `lo0`. A char array that is completely filled has no terminating NUL, so its whole size is compared. A NULL or unreadable string equals no literal, not even `""`.

The comparison calls `bpfsnoop_str_eq()` in [bpf/bpfsnoop_str.h](../bpf/bpfsnoop_str.h). bpfsnoop puts the literals in its `.rodata.strlit` section, 256 bytes each, and their lengths in `.rodata.strlit.length` when loading the bpf prog. The string is read once with `bpf_probe_read_kernel_str()` to a 256-byte buffer reserved from the event ringbuf of the CPU, which gives its length. A different length ends the comparison. Otherwise, the string is compared with the literal with `bpf_strncmp()`, or 8 bytes at a time on kernels before 5.17, which lack it.

The buffer is discarded in the end without waking the reader of the ringbuf, which bpfsnoop wakes every 100 ms if its ringbuf has unread records. The events after such a buffer wait for it, so they're output up to 100 ms later. If the ringbuf fills up in between, e.g. with a function called hundreds of thousands of times a second on a CPU, the string equals no literal.
