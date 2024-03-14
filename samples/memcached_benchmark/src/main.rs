// use async_memcached::*;
use clap::{Parser, Subcommand, ValueEnum};
use memcache::MemcacheError;
use rand::distributions::{Alphanumeric, DistString, Distribution};
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use serde_json::json;

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::mem::size_of_val;
use std::result::Result;
use std::vec;
use std::{collections::HashMap, sync::Arc};

use rayon::prelude::*;
use tokio::net::UdpSocket;
use tokio::runtime::Builder;
// use tokio::runtime::Runtime;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::timeout;

// use tokio::runtime::Handle;
use std::sync::atomic::*;
use tokio::task::JoinSet;
use tokio_util::task::TaskTracker;

const BUFFER_SIZE: usize = 1500;
const SEED: u64 = 12312;
const BENCH_ENTRIES_PATH: &str = "bench_entries.yml.zst";

static TIMEOUT_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum Protocol {
    Udp,
    Tcp,
}

struct TaskData {
    buf: Vec<u8>,
    addr: Arc<String>,
    key: String,
    test_dict: Arc<HashMap<String, String>>,
    validate: bool,
    key_size: usize,
    value_size: usize,
    counter: usize,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Bench {
        /// memcached server addr
        #[arg(short, long, required = true)]
        server_address: String,

        #[arg(short, long, default_value = "11211")]
        port: String,

        /// key size to generate random memcached key
        #[arg(short, long, default_value = "16")]
        key_size: usize,

        /// value size to generate random memcached value
        #[arg(short, long, default_value = "32")]
        value_size: usize,

        /// verify the value after get command
        #[arg(long, default_value = "false")]
        validate: bool,

        /// number of test entries to generate
        #[arg(short, long, default_value = "100000")]
        nums: usize,

        /// number of threads to run
        #[arg(short, long, default_value = "4")]
        threads: usize,

        /// udp or tcp protocol for memcached
        #[arg(short = 'l', long, default_value_t = Protocol::Udp , value_enum)]
        protocol: Protocol,

        /// number of dict entries to generate
        #[arg(short, long, default_value = "1000000")]
        dict_entries: usize,

        /// load the prepared test_entries from disk
        #[arg(long, default_value = "false")]
        load_bench_entries: bool,

        /// skip set memcached value if the data is already imported
        #[arg(long, default_value = "false")]
        skip_set: bool,

        /// bounded mpsc channel for communicating between asynchronous tasks with backpressure
        #[arg(long, default_value = "200")]
        pipeline: usize,

        /// dict path to load
        #[arg(
            short = 'f',
            long,
            default_value = "test_dict.yml.zst",
            conflicts_with = "key_size",
            conflicts_with = "dict_entries"
        )]
        dict_path: String,
    },
    GenTestdict {
        /// key size to generate random memcached key
        #[arg(short, long, default_value = "16")]
        key_size: usize,

        /// value size to generate random memcached value
        #[arg(short, long, default_value = "32")]
        value_size: usize,

        /// number of dict entries to generate
        #[arg(short, long, default_value = "1000000")]
        dict_entries: usize,

        /// dict path to store
        #[arg(short = 'f', long, default_value = "test_dict.yml.zst")]
        dict_path: String,
    },
}

fn generate_random_str(len: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

fn generate_memcached_test_dict(
    key_size: usize,
    value_size: usize,
    nums: usize,
) -> HashMap<String, String> {
    // random generate dict for memcached test
    (0..nums)
        .into_par_iter()
        .map(|_| {
            (
                generate_random_str(key_size),
                generate_random_str(value_size),
            )
        })
        .collect()
}

/// Generate test dict and write to disk
/// # Arguments
/// * `key_size` - key size
/// * `value_size` - value size
/// * `nums` - number of entries
/// * `dict_path` - dict path to store
/// # Returns
/// * `Result` - Result<HashMap<String, String>, std::io::Error>
/// # Example
/// ```rust
/// let test_dict = generate_test_dict_write_to_disk(16, 32, 100000, "test_dict.yml.zst");
/// ```
fn generate_test_dict_write_to_disk(
    key_size: usize,
    value_size: usize,
    nums: usize,
    dict_path: &str,
) -> Result<HashMap<String, String>, std::io::Error> {
    let test_dict = generate_memcached_test_dict(key_size, value_size, nums);
    println!("test dict len: {}", test_dict.len());
    if let Some((key, value)) = test_dict.iter().next() {
        println!("test dict key size: {}", size_of_val(key.as_str()));
        println!("test dict value size: {}", size_of_val(value.as_str()));
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "test dict is empty",
        ))?;
    }
    write_hashmap_to_file(&test_dict, dict_path)?;
    println!("write test dict to path {}", dict_path);
    Ok(test_dict)
}

async fn set_memcached_value<'a>(
    test_dict: Arc<HashMap<String, String>>,
    server_address: String,
    port: String,
) -> Result<(), MemcacheError> {
    let addr = format!("{}:{}", server_address, port);
    let mut sockets_pool = vec![];
    for _ in 0..64 {
        let client = async_memcached::Client::new(addr.as_str())
            .await
            .expect("TCP memcached connection failed");
        sockets_pool.push(Arc::new(tokio::sync::Mutex::new(client)));
    }
    let sockets_pool = Arc::new(sockets_pool);

    let mut set = JoinSet::new();

    for (count, (key, value)) in test_dict.iter().enumerate() {
        let sockets_pool_clone = sockets_pool.clone();
        let key_clone = key.clone();
        let value_clone = value.clone();
        set.spawn(async move {
            let mut socket = sockets_pool_clone[count & 0x3F].lock().await;

            socket
                .set(&key_clone, value_clone.as_bytes(), None, None)
                .await
                .expect("memcached set command failed");

            let ret = socket
                .get(&key_clone)
                .await
                .expect("memcached get command failed");

            let get_value = ret.unwrap();
            assert_eq!(get_value.data, value_clone.as_bytes());
        });
    }
    while !set.is_empty() {
        set.join_next().await;
    }

    println!("Done set memcached value");

    Ok(())
}

fn _validate_server(server: &memcache::Client) -> std::result::Result<(), MemcacheError> {
    // set a string value:
    server.set("foo", "bar", 0)?;

    // retrieve from memcached:
    let value: Option<String> = server.get("foo")?;
    assert_eq!(value, Some(String::from("bar")));
    assert_eq!(value.unwrap(), "bar");

    // prepend, append:
    server.prepend("foo", "foo")?;
    server.append("foo", "baz")?;
    let value: String = server.get("foo")?.unwrap();
    assert_eq!(value, "foobarbaz");

    // delete value:
    server.delete("foo").unwrap();

    // using counter:
    server.set("counter", 40, 0).unwrap();
    server.increment("counter", 2).unwrap();
    let answer: i32 = server.get("counter")?.unwrap();
    assert_eq!(answer, 42);

    // flush the database:
    server.flush()?;

    println!("memcached server works!");
    Ok(())
}

fn wrap_get_command(key: String, seq: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0, 0, 0, 1, 0, 0];
    let mut command = format!("get {}\r\n", key).into_bytes();
    let mut seq_bytes = seq.to_be_bytes().to_vec();
    seq_bytes.append(&mut bytes);
    seq_bytes.append(&mut command);
    // println!("bytes: {:?}", seq_bytes);
    seq_bytes
}

async fn socket_task<'a>(
    sockets_pool: Arc<Vec<UdpSocket>>,
    mut rx: mpsc::Receiver<TaskData>,
    tracker: TaskTracker,
) {
    let mut cnt = 0u64;
    while let Some(TaskData {
        buf,
        addr,
        key,
        test_dict,
        validate,
        key_size,
        value_size,
        counter,
    }) = rx.recv().await
    {
        let socket_pool_clone = Arc::clone(&sockets_pool);
        cnt += 1;
        tracker.spawn(async move {
            // Send
            let socket: &UdpSocket = &socket_pool_clone[counter & 0x1F];
            let _ = socket.send_to(&buf[..], addr.as_str()).await;

            // Then receive
            let mut buf = [0; BUFFER_SIZE];
            let my_duration = tokio::time::Duration::from_millis(500);

            if let Ok(Ok((amt, _))) = timeout(my_duration, socket.recv_from(&mut buf)).await {
                if !validate {
                    return;
                }
                if let Some(value) = test_dict.get(&key) {
                    let received = String::from_utf8_lossy(&buf[..amt])
                        .split("VALUE ")
                        .nth(1)
                        .unwrap_or_default()[6 + key_size + 1..6 + key_size + value_size + 1]
                        .to_string();

                    if received != *value.to_string() {
                        println!(
                            "response not match key {} buf: {} , value: {}",
                            key, received, value
                        );
                    }
                }
            } else {
                // Timeout occurred - increment the counter
                TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    println!("processed tasks: {}", cnt);
}

async fn get_command_benchmark(
    test_dict: Arc<HashMap<String, String>>,
    send_commands: Vec<(String, Vec<u8>, Protocol, String)>,
    server_address: String,
    port: String,
    validate: bool,
    key_size: usize,
    value_size: usize,
    pipeline: usize,
) -> Result<(), Box<dyn Error>> {
    // assign client address
    let addr = Arc::new(format!("{}:{}", server_address, port));

    let mut sockets_pool = vec![];
    for _ in 0..32 {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("couldn't bind to address");
        sockets_pool.push(socket);
    }
    let sockets_pool = Arc::new(sockets_pool);

    let mut client = async_memcached::Client::new(format!("{}:{}", server_address, port))
        .await
        .expect("TCP memcached connection failed");

    let tracker = TaskTracker::new();
    let cloned_tracker = tracker.clone();

    let start = std::time::Instant::now();

    // Create the channel
    let (tx, rx) = mpsc::channel(pipeline);

    tracker.spawn(socket_task(sockets_pool, rx, cloned_tracker));

    let mut counter = 0usize;
    let mut handles = vec![];

    for (key, packet, proto, value) in send_commands {
        // if tcp, use set request
        if proto == Protocol::Tcp {
            client
                .set(&key, value.as_bytes(), None, None)
                .await
                .expect("memcached set command failed");
            continue;
        }
        counter = counter.wrapping_add(1);
        let send_result = tx.send(TaskData {
            buf: packet,
            addr: addr.clone(),
            key,
            test_dict: test_dict.clone(),
            validate,
            key_size,
            value_size,
            counter,
        });
        handles.push(send_result);
    }

    for handle in handles {
        handle.await?;
        // let metrics = Handle::current().metrics();
        // let n = metrics.active_tasks_count();
    }

    // Close the channel
    drop(tx);

    // Wait for the socket task to finish
    tracker.close();
    tracker.wait().await;

    let duration = start.elapsed();
    println!("Time elapsed in get_command_benchmark() is: {:?}", duration);

    Ok(())
}

fn get_server(
    addr: &String,
    port: &String,
    protocol: &Protocol,
) -> Result<memcache::Client, MemcacheError> {
    match protocol {
        Protocol::Udp => memcache::connect(format!("memcache+udp://{}:{}?timeout=10", addr, port)),
        Protocol::Tcp => memcache::connect(format!("memcache://{}:{}?timeout=10", addr, port)),
    }
}

// Make the function generic over `T` where `T: Serialize`
fn write_hashmap_to_file<T: Serialize>(hashmap: &T, file_path: &str) -> std::io::Result<()> {
    // Serialize the hashmap to a JSON string
    let serialized = serde_yaml::to_string(hashmap).expect("Failed to serialize");

    // Create or open the file
    let file = File::create(file_path)?;

    // Create a zstd encoder with default compression level
    let mut encoder = zstd::stream::write::Encoder::new(file, 7)?;

    // Write the JSON string to the file
    encoder.write_all(serialized.as_bytes())?;
    encoder.finish()?;

    Ok(())
}

// INFO: May need to update based on key and value distributions
fn test_entries_statistics(test_entries: Arc<Vec<(&String, &String, Protocol)>>) {
    let mut udp_count: usize = 0;
    let mut tcp_count: usize = 0;

    // analyze the key distribution base on the frequency
    let mut key_frequency = HashMap::new();

    // only get the first element in the tuple
    test_entries.iter().for_each(|(key, _, proto)| {
        *key_frequency.entry(key.to_string()).or_insert(0) += 1;
        if *proto == Protocol::Udp {
            udp_count += 1;
        } else {
            tcp_count += 1;
        }
    });

    // sort by frequency
    let mut key_frequency: Vec<_> = key_frequency.into_iter().collect();
    key_frequency.sort_by(|a, b| a.1.cmp(&b.1));

    // Display the frequency of each item
    for (key, count) in &key_frequency {
        if *count < key_frequency.len() / 1000 {
            continue;
        }
        println!("{}: {}", key, count);
    }

    println!("tcp count: {}, udp count: {}", tcp_count, udp_count);
}

fn load_bench_entries_from_disk() -> Vec<(String, String, Protocol)> {
    let file = File::open(BENCH_ENTRIES_PATH).unwrap();
    let decoder = zstd::stream::read::Decoder::new(file).unwrap();
    let reader = BufReader::new(decoder);
    let test_entries: Vec<(String, String, Protocol)> = serde_yaml::from_reader(reader).unwrap();
    test_entries
}

fn generate_test_entries(
    test_dict: &Arc<HashMap<String, String>>,
    nums: usize,
) -> Vec<(&String, &String, Protocol)> {
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let zipf = zipf::ZipfDistribution::new(test_dict.len() - 1, 0.99).unwrap();

    let mut counter: usize = 0;
    let keys: Vec<&String> = test_dict.keys().collect();
    (0..nums)
        .map(|_| {
            let key = keys[zipf.sample(&mut rng)];
            let value = test_dict.get(key).unwrap();
            // every 31 element is tcp. udp:tcp = 30:1
            let protocol = if counter % 31 == 30 {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            counter += 1;
            (key, value, protocol)
        })
        .collect()
}

fn load_test_dict(
    test_dict_path: &std::path::Path,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    // load dict from file if dict_path is not empty
    println!("load dict from path {:?}", test_dict_path);
    let file = File::open(test_dict_path)?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
    let reader = BufReader::new(decoder);

    // Deserialize the string into a HashMap
    let mut test_dict = HashMap::new();

    reader.lines().for_each(|line| {
        let line = line.unwrap();
        // Assuming each line in your file is a valid YAML representing a key-value pair
        let deserialized_map: HashMap<String, String> = serde_yaml::from_str(&line).unwrap();
        test_dict.extend(deserialized_map);
    });

    println!("test dict len: {}", test_dict.len());
    println!(
        "test dict key size: {}",
        test_dict.keys().next().unwrap().len()
    );
    println!(
        "test dict value size: {}",
        test_dict.values().next().unwrap().len()
    );
    Ok(test_dict)
}

fn run_bench() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let Commands::Bench {
        server_address,
        port,
        key_size,
        value_size,
        validate,
        nums,
        threads,
        protocol,
        dict_path,
        load_bench_entries,
        dict_entries,
        skip_set,
        pipeline,
    } = args.command
    else {
        return Err("invalid command".into());
    };

    let server = get_server(&server_address, &port, &protocol)?;

    let test_dict_path = std::path::Path::new(dict_path.as_str());
    let test_dict: HashMap<String, String> = if !test_dict_path.exists() {
        // if dict_path is empty, generate dict
        generate_test_dict_write_to_disk(key_size, value_size, dict_entries, dict_path.as_str())?
    } else {
        load_test_dict(test_dict_path)?
    };
    let test_dict = Arc::new(test_dict);

    // if memcached server is already imported, skip set memcached value
    if !skip_set {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .worker_threads(512)
            .event_interval(31)
            .build()?;

        let test_dict = test_dict.clone();
        let server_address = server_address.clone();
        let port = port.clone();
        rt.block_on(async move {
            set_memcached_value(test_dict, server_address, port)
                .await
                .unwrap()
        });
    }

    let test_dict_path = std::path::Path::new(BENCH_ENTRIES_PATH);
    let test_entries_tmp = if load_bench_entries && test_dict_path.exists() {
        load_bench_entries_from_disk()
    } else {
        vec![]
    };

    let test_entries = if test_entries_tmp.is_empty() {
        let test_entries = generate_test_entries(&test_dict, nums);
        if load_bench_entries {
            write_hashmap_to_file(&test_entries, BENCH_ENTRIES_PATH)?;
        }
        test_entries
    } else {
        // convert to Vec<(&String, &String, Protocol)>
        test_entries_tmp
            .iter()
            .map(|(key, value, proto)| (key, value, *proto))
            .collect()
    };
    let test_entries = Arc::new(test_entries);

    // analyze test entries statistics
    test_entries_statistics(test_entries.clone());

    let mut send_commands_vec = Vec::new();

    // First generate get commands for each thread
    for thread_num in 0..threads {
        let mut seq: u16 = 0;
        let mut send_commands = vec![];

        for index in 0..nums / threads {
            let (key, value, proto) = test_entries[thread_num * nums / threads + index];
            let packet = wrap_get_command(key.clone(), seq);
            seq = seq.wrapping_add(1);
            send_commands.push((key.to_string(), packet, proto, value.to_string()));
        }

        send_commands_vec.push(send_commands);
    }

    let start_time = std::time::SystemTime::now();

    // let rt = Builder::new_multi_thread().enable_all().build()?;
    let mut handles = vec![];

    for tid in 0..threads {
        let test_dict = Arc::clone(&test_dict);
        let server_address = server_address.clone();
        let port = port.clone();
        let send_commands = send_commands_vec.pop().unwrap();
        let handle = std::thread::Builder::new()
            .name(format!("bmc-worker-{tid}"))
            .spawn(move || {
                let rt = Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    get_command_benchmark(
                        test_dict,
                        send_commands,
                        server_address,
                        port,
                        validate,
                        key_size,
                        value_size,
                        pipeline,
                    )
                    .await
                    .unwrap()
                })
            })
            .unwrap();
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // wait for all tasks to complete
    println!("wait for all tasks to complete");

    let elapsed_time = start_time.elapsed()?.as_secs_f64();
    println!("Timeout counter {}", TIMEOUT_COUNTER.load(Ordering::SeqCst));
    let throughput = (nums - TIMEOUT_COUNTER.load(Ordering::SeqCst)) as f64 / elapsed_time;
    println!(
        "Throughput across all threads: {:.2} reqs/sec, elapsed_time {}",
        throughput, elapsed_time
    );

    macro_rules! build_stats_map {
    ($result:expr, $($key:expr),*) => {{
        let mut map = ::std::collections::HashMap::new();
        $(
            map.insert($key, &$result[$key]);
        )*
        map
    }};
}

    // stats
    let stats = server.stats()?;
    let result = &stats[0].1;
    let output = build_stats_map!(
        result,
        "cmd_get",
        "cmd_set",
        "get_hits",
        "get_misses",
        "bytes_read",
        "bytes_written",
        "curr_items",
        "total_items"
    );
    let obj = json!(output);
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    match args.command {
        Commands::Bench { .. } => {
            run_bench()?;
        }
        Commands::GenTestdict {
            key_size,
            value_size,
            dict_entries,
            dict_path,
        } => {
            let _ = generate_test_dict_write_to_disk(
                key_size,
                value_size,
                dict_entries,
                dict_path.as_str(),
            )?;
        }
    }

    Ok(())
}
