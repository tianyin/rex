// use async_memcached::*;
use clap::{Parser, Subcommand, ValueEnum};
use futures::future::join_all;
use memcache::MemcacheError;
use rand::distributions::{Alphanumeric, DistString, Distribution};
use serde_yaml;
use zstd;

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::mem::size_of_val;
use std::result::Result;
use std::vec;
use std::{collections::HashMap, sync::Arc};

use rayon::prelude::*;
use std::net::UdpSocket as StdUdpSocket;
use tokio::net::UdpSocket;
use tub::Pool;

use tokio::sync::mpsc;
use tokio::time::timeout;

extern crate r2d2_memcache;

const BUFFER_SIZE: usize = 1500;

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
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

        /// skip set memcached value if the data is already imported
        #[arg(long, default_value = "false")]
        skip_set: bool,

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

async fn set_memcached_value(
    test_dict: Arc<HashMap<String, String>>,
    server_address: String,
    port: String,
) -> Result<(), MemcacheError> {
    let manager = r2d2_memcache::MemcacheConnectionManager::new(format!(
        "memcache://{}:{}",
        server_address, port
    ));
    let pool = r2d2_memcache::r2d2::Pool::builder()
        .max_size(100)
        .build(manager)
        .unwrap();

    test_dict.par_iter().for_each(|(key, value)| {
        let conn = pool.get().unwrap();
        conn.set(key, value.as_bytes(), 0).unwrap();
        let result: String = conn.get(key).unwrap().unwrap();
        assert!(result == *value);
    });

    println!("Done set memcaced value");

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

async fn socket_task(socket: Arc<UdpSocket>, mut rx: mpsc::Receiver<TaskData>) {
    while let Some(TaskData {
        buf,
        addr,
        key,
        test_dict,
        validate,
        key_size,
        value_size,
    }) = rx.recv().await
    {
        // Send
        let _ = socket.send_to(&buf[..], addr.as_str()).await;

        // Then receive
        let mut buf = [0; BUFFER_SIZE];
        let my_duration = tokio::time::Duration::from_millis(500);

        if let Ok(Ok((amt, _))) = timeout(my_duration, socket.recv_from(&mut buf)).await {
            if !validate {
                continue;
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
        }
    }
}

async fn get_command_benchmark(
    test_dict: Arc<HashMap<String, String>>,
    send_commands: Vec<(String, Vec<u8>, Protocol, String)>,
    server_address: String,
    port: String,
    validate: bool,
    key_size: usize,
    value_size: usize,
) -> Result<(), Box<dyn Error>> {
    // assign client address
    let addr = Arc::new(format!("{}:{}", server_address, port));
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);
    // let addr_to: ToSocketAddrs = ToSocketAddrs::to_socket_addrs(addr).unwrap();

    let conn = memcache::connect(format!("memcache://{}:{}?timeout=10", server_address, port))?;

    let start = std::time::Instant::now();

    // Create the channel
    let (tx, rx) = mpsc::channel(100000);
    let socket_clone = Arc::clone(&socket);
    let socket_task = tokio::spawn(socket_task(socket_clone, rx));

    for (key, packet, proto, value) in send_commands {
        // if tcp, use set request
        if proto == Protocol::Tcp {
            conn.set(&key, value.as_bytes(), 0)?;
            continue;
        }
        let send_result = tx
            .send(TaskData {
                buf: packet,
                addr: addr.clone(),
                key,
                test_dict: test_dict.clone(),
                validate,
                key_size,
                value_size,
            })
            .await;
        if send_result.is_err() {
            // The receiver was dropped, break the loop
            break;
        }
    }

    // Close the channel
    drop(tx);

    // Wait for the socket task to finish
    socket_task.await?;

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

fn write_hashmap_to_file(
    hashmap: &HashMap<String, String>,
    file_path: &str,
) -> std::io::Result<()> {
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

fn generate_test_entries<'a>(
    test_dict: &'a Arc<HashMap<String, String>>,
    nums: usize,
) -> Vec<(&'a String, &'a String, Protocol)> {
    let mut rng = rand::thread_rng();
    let zipf = zipf::ZipfDistribution::new(test_dict.len() - 1, 0.99).unwrap();

    let mut counter: usize = 0;
    let keys: Vec<&String> = test_dict.keys().collect();
    (0..nums)
        .into_iter()
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

async fn run_bench() -> Result<(), Box<dyn Error>> {
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
        dict_entries,
        skip_set,
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
        set_memcached_value(test_dict.clone(), server_address.clone(), port.clone()).await?;
    }

    // generate test entries
    let test_entries = Arc::new(generate_test_entries(&test_dict, nums));

    // analyze test entries statistics
    test_entries_statistics(test_entries.clone());

    // UDP:TCP = 30:1 and the total number of clients is 340
    // generate udp socket pool
    let _udp_pool: Pool<StdUdpSocket> = (0..328)
        .map(|_| StdUdpSocket::bind("0.0.0.0:0").unwrap())
        .into();

    // generate tcp connect pool
    let manager = r2d2_memcache::MemcacheConnectionManager::new(format!(
        "memcache://{}:{}",
        server_address, port
    ));
    let _tcp_pool = r2d2_memcache::r2d2::Pool::builder()
        .max_size(11)
        .build(manager)
        .unwrap();

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

    let mut handles = vec![];

    let start_time = std::time::SystemTime::now();

    for _ in 0..threads {
        let test_dict = Arc::clone(&test_dict);
        let server_address = server_address.clone();
        let port = port.clone();
        let send_commands = send_commands_vec.pop().unwrap();
        let handle = tokio::spawn(async move {
            match get_command_benchmark(
                test_dict,
                send_commands,
                server_address,
                port,
                validate,
                key_size,
                value_size,
            )
            .await
            {
                Ok(_) => (),
                Err(e) => eprintln!("Task failed with error: {:?}", e),
            }
        });
        handles.push(handle);
    }
    // wait for all tasks to complete
    println!("wait for all tasks to complete");
    join_all(handles).await;

    let elapsed_time = start_time.elapsed()?.as_secs_f64();
    let throughput = nums as f64 / elapsed_time;
    println!("Throughput across all threads: {:.2} reqs/sec", throughput);

    // stats
    let stats = server.stats()?;
    println!("stats: {:?}", stats);
    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    match args.command {
        Commands::Bench { .. } => {
            run_bench().await?;
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
