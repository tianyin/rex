### Rex subset of Rust

- `std`
  - depends on libc, therefore not available in standalone mode
- `alloc`
  - Rex currently does not hook onto kernel's allocator
- unsafe
  - can break any safety guarrantee
- `core::mem::forget` and `core::mem::ManuallyDrop`
  - take ownership and “forget” about the value **without running its
    destructor**.
  - lifetime related: disrupts resource cleanup
- `core::intrinsics::abort`:
  - uses an illegal instruction and therefore can crash the kernel.
- `core::simd`
  - no simd/fp allowed in the kernel in the first place
