#![no_std]
#![no_main]

extern crate rex;

use rex::map::*;
use rex::tracepoint::*;
use rex::{bpf_printk, entry_link, rex_map, Result};

#[rex_map]
static MAP_HASH: RexHashMap<u32, i64> = RexHashMap::new(1024, 0);

#[rex_map]
static ARRAY: RexArray<i64> = RexArray::new(256, 0);

#[rex_map]
static STACK: RexStack<i64> = RexStack::new(256, 0);

#[rex_map]
static QUEUE: RexQueue<i64> = RexQueue::new(256, 0);

// #[rex_map]
// static RINGBUF: IURingBuf = IURingBuf::new(4096, 0);

fn map_test_hash(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, "Map Testing Hash Start with key %u\n", key as u64);

    match MAP_HASH.get_mut(&key) {
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

    MAP_HASH.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, "Map Updated\n");

    match MAP_HASH.get_mut(&key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    MAP_HASH.delete(&key)?;
    bpf_printk!(obj, "Map delete key\n");

    match MAP_HASH.get_mut(&key) {
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

    ARRAY.insert(&key, &(pid as i64))?;
    bpf_printk!(obj, "Map Updated\n");

    match ARRAY.get_mut(&key) {
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

    STACK.push(&(pid as i64))?;
    bpf_printk!(obj, "Pushed %llu onto stack\n", pid as u64);

    STACK.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, "Pushed %llu onto stack\n", (pid + 1) as u64);

    match STACK.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(top) => bpf_printk!(obj, "Top of stack: %llu\n", top as u64),
    };

    STACK.pop();
    bpf_printk!(obj, "Popped top of stack\n");

    match STACK.peek() {
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

    QUEUE.push(&(pid as i64))?;
    bpf_printk!(obj, "Pushed %llu into queue\n", pid as u64);

    QUEUE.push(&((pid + 1) as i64))?;
    bpf_printk!(obj, "Pushed %llu into queue\n", (pid + 1) as u64);

    match QUEUE.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(front) => bpf_printk!(obj, "Front of queue: %llu\n", front as u64),
    };

    QUEUE.pop();
    bpf_printk!(obj, "Popped front of queue\n");

    match QUEUE.peek() {
        None => bpf_printk!(obj, "Not found.\n"),
        Some(next_front) => bpf_printk!(obj, "Next front of queue: %llu\n", next_front as u64),
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
    // map_test_ringbuf(obj).map_err(|e| {
    //     bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
    //     e
    // })?;
    map_test_queue(obj).map_err(|e| {
        bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
        e
    })
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
