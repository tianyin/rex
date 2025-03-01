#![no_std]
#![no_main]

extern crate rex;

use rex::map::*;
use rex::rex_tracepoint;
use rex::tracepoint::*;
use rex::{Result, bpf_printk, rex_map};

#[rex_map]
static MAP_HASH: RexHashMap<u32, i64> = RexHashMap::new(1024, 0);

#[rex_map]
static ARRAY: RexArrayMap<i64> = RexArrayMap::new(256, 0);

#[rex_map]
static STACK: RexStack<i64> = RexStack::new(256, 0);

#[rex_map]
static QUEUE: RexQueue<i64> = RexQueue::new(256, 0);

// #[rex_map]
// static RINGBUF: IURingBuf = IURingBuf::new(4096, 0);

fn map_test_hash(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, c"Map Testing Hash Start with key %u\n", key as u64);

    match MAP_HASH.get_mut(&key) {
        None => {
            bpf_printk!(obj, c"Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, c"Found Val=%llu.\n", (*val) as u64);
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, c"Rust program triggered from PID %llu\n", pid as u64);

    MAP_HASH.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, c"Map Updated\n");

    match MAP_HASH.get_mut(&key) {
        None => {
            bpf_printk!(obj, c"Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, c"Found Val=%llu.\n", (*val) as u64);
        }
    }

    MAP_HASH.delete(&key)?;
    bpf_printk!(obj, c"Map delete key\n");

    match MAP_HASH.get_mut(&key) {
        None => {
            bpf_printk!(obj, c"Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, c"Found Val=%llu.\n", (*val) as u64);
        }
    }

    Ok(0)
}

fn map_test_array(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, c"Map Testing Array Start with key %u\n", key as u64);

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, c"Rust program triggered from PID %llu\n", pid as u64);

    ARRAY.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, c"Map Updated\n");

    match ARRAY.get_mut(&key) {
        None => {
            bpf_printk!(obj, c"Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, c"Found Val=%llu.\n", (*val) as u64);
        }
    }

    Ok(0)
}

fn map_test_stack(obj: &tracepoint) -> Result {
    bpf_printk!(obj, c"Map Testing Stack Start\n");

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, c"Rust program triggered from PID %llu\n", pid as u64);

    STACK.push(&(pid as i64))?;
    bpf_printk!(obj, c"Pushed %llu onto stack\n", pid as u64);

    STACK.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, c"Pushed %llu onto stack\n", (pid + 1) as u64);

    match STACK.peek() {
        None => bpf_printk!(obj, c"Not found.\n"),
        Some(top) => bpf_printk!(obj, c"Top of stack: %llu.\n", top as u64),
    };

    STACK.pop();
    bpf_printk!(obj, c"Popped top of stack\n");

    match STACK.peek() {
        None => bpf_printk!(obj, c"Not found.\n"),
        Some(next_top) => {
            bpf_printk!(obj, c"Next top of stack: %llu.\n", next_top as u64)
        }
    };

    Ok(0)
}

fn map_test_queue(obj: &tracepoint) -> Result {
    bpf_printk!(obj, c"Map Testing Queue Start\n");

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, c"Rust program triggered from PID %llu\n", pid as u64);

    QUEUE.push(&(pid as i64))?;
    bpf_printk!(obj, c"Pushed %llu into queue\n", pid as u64);

    QUEUE.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, c"Pushed %llu into queue\n", (pid + 1) as u64);

    match QUEUE.peek() {
        None => bpf_printk!(obj, c"Not found.\n"),
        Some(front) => {
            bpf_printk!(obj, c"Front of queue: %llu.\n", front as u64)
        }
    };

    QUEUE.pop();
    bpf_printk!(obj, c"Popped front of queue\n");

    match QUEUE.peek() {
        None => bpf_printk!(obj, c"Not found.\n"),
        Some(next_front) => {
            bpf_printk!(obj, c"Next front of queue: %llu.\n", next_front as u64)
        }
    };
    Ok(0)
}

/*
fn map_test_ringbuf(obj: &tracepoint) -> Result {
    bpf_printk!(obj, "Map Testing Ring Buffer Start\n");
    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    bpf_printk!(obj, "Available bytes in ringbuf: %llu\n", RINGBUF.available_bytes().unwrap());

    let entry = match RINGBUF.reserve::<i64>(true, pid as i64) {
        None => {
            bpf_printk!(obj, "Unable to reserve ringbuf.\n");
            return Err(0);
        }
        Some(entry) => entry,
    };

    entry.submit();

    bpf_printk!(obj, "Available bytes in ringbuf: %llu\n", RINGBUF.available_bytes().unwrap());

    Ok(0)
}
*/

#[rex_tracepoint(name = "syscalls/sys_enter_dup", tp_type = "Void")]
fn rex_prog1(obj: &tracepoint, _: tp_ctx) -> Result {
    map_test_hash(obj).inspect_err(|&e| {
        bpf_printk!(obj, c"map_test failed with %lld.\n", e as u64);
    })?;
    map_test_array(obj).inspect_err(|&e| {
        bpf_printk!(obj, c"map_test failed with %lld.\n", e as u64);
    })?;
    map_test_stack(obj).inspect_err(|&e| {
        bpf_printk!(obj, c"map_test failed with %lld.\n", e as u64);
    })?;
    // map_test_ringbuf(obj).inspect_err(|&e| {
    //     bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
    // })?;
    map_test_queue(obj).inspect_err(|&e| {
        bpf_printk!(obj, c"map_test failed with %lld.\n", e as u64);
    })
}
