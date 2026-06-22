# manualmap

x64 manual-mapping DLL injector for Windows, built as a Rust cdylib.

Handles relocations, imports, TLS, and calls `DllMain(DLL_PROCESS_ATTACH)` in the target.

## Build

```
cargo build --release
```

Produces `target/release/manualmap.dll`.

## API

```c
extern int injector_run(
    uint32_t pid,
    const uint8_t* dll, size_t dll_len,
    uint32_t flags);
```

Returns 0 on success, negative `E_*` code on failure (see `src/lib.rs`).

## License

MIT
