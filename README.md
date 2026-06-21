# manualmap

x64 manual-mapping DLL injector cdylib for Windows.

## Build

```
cargo build --release
```

Output: `target/release/manualmap.dll`.

## Use

```c
extern int injector_run(
    uint32_t pid,
    const uint8_t* dll, size_t dll_len,
    uint32_t flags);
```

Maps the DLL into the target PID and runs `DllMain(DLL_PROCESS_ATTACH)`.
Returns 0 on success or a negative `codes::E_*` on failure (see `src/lib.rs`).

## License

MIT.
