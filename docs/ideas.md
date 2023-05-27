While we are focusing on the mainstream of inner unikernel. 
There are a few interesting ideas popping up. 
We are going to do them later when the infra is more ready, so let me document them first.

## 1. Fuzzing the helpers

For kernel extensions, helpers are analogous to syscalls for a userspace program 
and are likely the only unsafe components of the extension code.
Therefore, their security and reliability are crucial. 
Similar as syscalls, it is not hard to imagine that there will be more and more helpers. 
So, just like how folks are fuzzing syscalls, we can build a helper fuzzer to fuzz the helper interface.

## 2. Compatibility of kernel extensions

@Jinghao finds that the BMC code already can't work, likely due to the evlution of the verifier.
@Dan raises a great point that this is almost unlikely to happen for Linux programs due to strict ABI.
An interesting side project is to look at the compatibility of kernel extension programs.
