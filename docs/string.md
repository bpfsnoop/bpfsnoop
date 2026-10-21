# Comparing strings

`--filter-arg` and `--output-arg` can compare a string with a string literal through `str()`:

```sh
bpfsnoop -k security_file_open \
  --filter-arg 'str(file->f_path.dentry->d_name.name) == "passwd"'

bpfsnoop -k generic_xdp_install --filter-arg 'str(dev->name) != "lo"'
```

The argument of `str()` must be a char pointer or a char array, including `unsigned char` and `u8`. Only `==` and `!=` with a string literal are supported. The literal can be on either side, can use escapes like `"\t"`, and is at most 256 bytes. In `--output-arg`, the comparison is output as a bool.

The comparison is exact: `str(dev->name) == "lo"` doesn't match `lo0`. A char array that is completely filled has no terminating NUL, so its whole size is compared. A NULL or unreadable string only equals `""`.

As in bpftrace, the comparison is unrolled when compiling, because the length of the literal is known: the string is read with `bpf_probe_read_kernel()` in chunks of up to 8 bytes, and each chunk is compared with a constant. The first different chunk ends the comparison. No loop or newer helper is needed, so it works on all kernels that bpfsnoop supports.
