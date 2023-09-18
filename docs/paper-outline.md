- Abstract & introduction
  - eBPF is the de-facto way of doing kernel extension in Linux
  - Used in difference domains
    - networking, tracing, security
    - also embraced by research community (BMC, XRP, Electrode)
  - Core value argument: verification for safety
  - Problem: current static verification scheme (i.e. the verifier) places
    unnecesary constraints on expressiveness on extension programs
    - BMC has a subsection discussing verification workarounds
    - We had an unpleasant experience in porting BMC (though this is more like
      the new compiler does not play well with the verifier for some old code)
    - some more evidence/example needed
  - Another point I would like to include: for certain safety properties static
    verification is fundamentally limited even in current eBPF
    - from Roop's experiment: there is not a way for verifier to figure out
      statically how much stack will be used when bpf2bpf calls and tail calls
      are mixed due to the indirect nature of tail calls. If the stack is 8k
      (e.g. on 32-bit platforms) the verifier cannot protect the stack.
    - This is sort of related to our argument on runtime mechanism
  - Our solution: we should use a more expressive language for kernel extensions
    and move away from the verifier. The language should:
    - be Turing complete (or does it?)
    - support equivalent safety properties as the verifier (the hotos table)
      - memory safety
      - control-flow safety
      - type safety
      - safe resource management
      - program termination
      - kernel stack overflow protection
    - Rust
      - a widely used high-level programming language, also embraced by Linux
        (Rust for Linux)
      - happens to have most of these properties out-of-box, therefore we
        choose to build upon Rust
- Background
  - eBPF verification
  - Rust
- Design
  - Rust based approach
  - how to ensure safety
    - builtin memory/control/type safety
      - generic and const-generic functions to prevent OOB access
      - Safe direct packet access for XDP programs
      - Retired expressiveness kernel helpers
    - RAII
    - runtime mechanism to support properties that are (fundamentally) hard to
      check at compile time
      - program termination
      - stack overflow protection
    - exception handling and stack unwinding
      - handle exceptional control flow
      - clean up resources to achieve RAII under exceptional circumstances
- Implementation
  - Overview of infrastructure (similar to Fig. 5 from HotOS paper)
  - program load and attachment
    - kernel loading code and attachment
    - libiu
  - runtime crate as the programming interface
    - program type (how Rust type system is leveraged) (feels like this should
      be in Design section, but at the same time this is pretty detailed that
      fits here)
    - kernel helper & symbol bindings
    - kconfig-based conditional compilation
  - Entry code generation
    - LLVM pass
  - Handle exceptional control flow
    - kernel trampoline
  - stack overflow protection
    - kernel vmapped, dedicated stack
    - LLVM instrumentation
  - program termination
    - WIP
- Evaluation
  - BMC
    - expressiveness: how to evaluate?
      - based on experience?
    - performance evaluation
  - More complicated extension programs?
