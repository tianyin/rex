### What we don't include in Rex

- `std`
  - depends on libc, therefore not available in standalone mode
- `alloc`
  - we currently do not hook onto kernel's allocator
- unsafe
  - can break any safety guarrantee
- `core::mem::forget`
  - takes ownership and “forgets” about the value **without running its
    destructor**.
  - lifetime related: disrupts resource cleanup
- `core::intrinsics`: ban everything except `likely()` and `unlikely()`
  - the available APIs are too low-level and most of the useful ones are
    already wrapped in high-level APIs, an example is atomics.
- `core::simd`
  - no simd/fp allowed in the kernel in the first place
- procedural macros
  - implicity disabled: we do not allow other third party crates and proc-macro
    has to be of a separate crate (because the code is compiled into an
    extension of `rustc`)
