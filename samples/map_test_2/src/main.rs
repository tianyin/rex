#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::map::{IUHashMap, IUArray, IUStack, IUQueue};
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{bpf_printk, entry_link, Result, ARRAY, HASH_MAP, STACK, QUEUE};

HASH_MAP!(map_hash, u32, i64, 1024, 0);
ARRAY!(map_array, i64, 256, 0);
STACK!(map_stack, i64, 256, 0);
QUEUE!(map_queue, i64, 256, 0);

fn map_test_hash(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, "Map Testing Hash Start with key %u\n", key as u64);

    match map_hash.get_mut(&key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    map_hash.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, "Map Updated\n");

    match map_hash.get_mut(&key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    map_hash.delete(&key)?;
    bpf_printk!(obj, "Map delete key\n");

    match map_hash.get_mut(&key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    Ok(0)
}

fn map_test_array(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, "Map Testing Array Start with key %u\n", key as u64);

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    map_array.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, "Map Updated\n");

    match map_array.get_mut(&key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu in array\n", (*val) as u64);
        }
    }

    Ok(0)
}

fn map_test_stack(obj: &tracepoint) -> Result {
    bpf_printk!(obj, "Map Testing Stack Start\n");

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    map_stack.push(&(pid as i64))?;
    bpf_printk!(obj, "Pushed %llu onto stack\n", pid as u64);

    map_stack.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, "Pushed %llu onto stack\n", (pid + 1) as u64);

    match map_stack.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(top) => bpf_printk!(obj, "Top of stack: %llu\n", top as u64),
    };

    map_stack.pop();
    bpf_printk!(obj, "Popped top of stack\n");

    match map_stack.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(next_top) => bpf_printk!(obj, "Next top of stack: %llu\n", next_top as u64),
    };

    Ok(0)
}

fn map_test_queue(obj: &tracepoint) -> Result {
    bpf_printk!(obj, "Map Testing Queue Start\n");

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    map_queue.push(&(pid as i64))?;
    bpf_printk!(obj, "Pushed %llu into queue\n", pid as u64);

    map_queue.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, "Pushed %llu into queue\n", (pid + 1) as u64);

    match map_queue.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(front) => bpf_printk!(obj, "Front of queue: %llu\n", front as u64),
    };

    map_queue.pop();
    bpf_printk!(obj, "Popped front of queue\n");

    match map_queue.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(next_front) => bpf_printk!(obj, "Next front of queue: %llu\n", next_front as u64),
    };
    Ok(0)
}

#[inline(always)]
fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    map_test_hash(obj).map_err(|e| {
        bpf_printk!(obj, "map_test1 failed with %lld.\n", e as u64);
        e
    })?;
    map_test_array(obj).map_err(|e| {
        bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
        e
    })?;
    map_test_stack(obj).map_err(|e| {
        bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
        e
    })?;
    map_test_queue(obj).map_err(|e| {
        bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
        e
    })
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
