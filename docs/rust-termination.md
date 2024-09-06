Quick guide to check if termination is supported for Rex programs
============
Currently, the termination code is supported only for BPF programs using
the helper `dummy_long_running_helper` defined in
[base_helper.rs](../rex/src/base_helpers.rs).

### Long running Rex program
In [samples/termination_test](../samples/termination_test) we have a Rex
program will call a dummy helper function that is intentionally made to
execute a time consuming loop.

### Steps :
  1. Start QEMU.

  2. cd into the [samples/termination_test](../samples/termination_test)

  3. In window 1, run the commands:

     ```bash
     $ taskset -c 1 ./loader & # This will load the program
     $ taskset -c 2 ./event-trigger & # This will trigger it.
     ```

     You can see a flood of prints that will denote the program is running.
     Also, any kind of Ctrl+C or other keyboard input shouldn't be able to
     stop the Rex execution.

  4. To stop the execution i.e. terminate the Rex program, just wait for
     the termination handler to be triggered in an interrupt.
