Quick guide to check if termination is supported for BPF programs
============
Currently, the termination code is supported only for BPF programs using the helper `dummy_long_running_helper` defined in base_helper.rs.

### Long running BPF program
In `linux/samples/hello/src/main.rs`, we have a BPF program will calls a dummy helper function that is intentionally 
made to execute a time consuming loop. 

### Steps : 
  1. Start QEMU in window 1, and ssh into the QEMU instance in window 2. 

  2. cd into the `linux/samples/hello` directory in window 1. 

  3. In window 1, run the commands : 
     ```bash
        $ taskset -c 1 ./loader & # This will load the hello BPF program
        $ taskset -c 2 ./event-trigger & # This will trigger it. 
     ```
  
   	You can see a flood of prints that will denote the program is running. 
    	Also, any kind of Ctrl+C or other keyboard input shouldn't be able to stop the BPF execution. 

  4. To stop the execution i.e. terminate the BPF program, in window 2:
     ```bash
 	$ bpftool prog show  # find the BPF prog ID from this command's output
        $ bpftool prog terminate <prog-ID-from-above> # call the termination API
     ```
	The execution may/may not stop instantly because the currently executing helper is waited upon to complete
	before stopping further execution. 


The tasksets are needed to keep the Window 2 from freezing (when the CPU behind the window becomes busy executing the BPF program)
