// Rust uses `use` to import modules.
// `pnet::datalink` is a module from the `pnet` crate (library).
// `self` means we import the `datalink` module itself.
use pnet::datalink;
// In this case we import the `Packet` trait from `pnet::packet`.
// Traits in Rust are like Go interfaces.
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use std::collections::HashMap;
// `Instant` is like Go's `time.Now()`, and `Duration` is like Go's
// `time.Duration`.
use std::time::{Instant, Duration};
// `Arc` is for letting multiple owners share data safely.
// `Mutex` is like Go's `sync.Mutex` for locking shared data.
use std::sync::{Arc, Mutex};

fn main() {
    // Get all network interfaces.
    // `let` declares a variable, immutable by default (unlike Go, unless `const`).
    // `interfaces` is a `Vec<NetworkInterface>` (Rust's dynamic array, like Go's
    // slice `[]net.Interfaces`).
    let interfaces = datalink::interfaces();

    // Print all interfaces for debugging.
    println!("Available interfaces:");
    for (i, iface) in interfaces.iter().enumerate() {
        println!(
            "[{}] {}: up={}, loopback={}",
            i, iface.name, iface.is_up(), iface.is_loopback()
        );
    }

    // Select an interface by name
    // `into_iter()` converts the `Vec` into an iterator, like a Go
    // `for _, iface := range interfaces`.
    // `find` is a method on iterators that returns an `Option` (like Go's
    // value, ok idiom but more explicit).
    // `|iface|` is a closure (anonymous function), like Go's `func(iface)`.
    // `&iface` borrows `iface` (Rust's way to avoid moving ownership).
    // Go's equivalent:
    // `for _, iface := range ifaces { if iface.Flags&net.FlagUp != 0 && ... }'.
    let interface = interfaces
        .into_iter()
        .find(|iface| {
            iface.name == "en0" && iface.is_up() && !iface.is_loopback()
        })
        // `expect` unwraps the `Option`, panicking with a message if `None`.
        // In Go, we'd panic manually: `if iface == nil { panic("no interface") }`.
        .expect(&format!("Interface '{}' not found or not suitable", "en0"));
    
    // `println!` is a macro, like Go's `fmt.Println`.
    // `{}` is a placeholder, filled by `interface.name`.
    println!("Using interface: {}", interface.name);

    // Open a packet capture channel on the interface.
    // `&interface` passes a reference (borrow), not the value itself.
    // `Default::default()` gives default config options, like Go's zero values.
    // `datalink::channel` returns a `Result`, Rust's way of handling errors (like Go's `value,
    // err`).
    // `match` is like Go's `switch`, but more powerful, it pattern-matches on the `Result`.
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        // `Ok` is the success case of `Result`, like `err == nil` in Go.
        // `datalink:Channel::Ethernet` is an enum variant, containing a
        // sender (`tx`) and receiver (`rx`).
        // In Go, this is like `handle, err := pcap.OpenLive(...)`.
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        // `_` is a wildcard, like Go's `_` for unused variables.
        // `panic!` crashes the program, like Go's `panic()`.
        Ok(_) => panic!("Unsupported channel type"),
        // `Err(e)` is the error case, `e` is the error value.
        // `{}` in `panic!` formats the error, like Go's `panic(fmt.Sprintf("Error: %v", e))`.
        Err(e) => panic!("Error opening channel: {}", e),
    };
    // `mut tx` and `mut rx` mean they’re mutable; Rust vars are immutable unless `mut` is added.
    // `tx` and `rx` are like Go channels, but here they’re for sending/receiving raw packets.
    
    // Create a thread-safe `HashMap` to track packet counts.
    // `Arc::new` wraps the `Mutex` in an atomic reference counter.
    // `Mutex::new` creates a mutex guarding the `HashMap`.
    // `HashMap<String, u32>` maps strings (source addresses) to 32-bit unsigned ints (counts).
    let packet_counts: Arc<Mutex<HashMap<String, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    // Track the last reset time for rate limiting.
    // `Instant::now()` is like Go’s `time.Now()`.
    // `Arc<Mutex<>>` again for thread safety; Rust requires this for shared mutable state.
    let last_reset = Arc::new(Mutex::new(Instant::now()));

    // Clone the `Arc`s for use in the loop.
    // `Arc::clone` increases the reference count, like copying a pointer in Go.
    // In Go, you’d just use the same `packetCounts` variable in a goroutine with a mutex.
    let counts_clone = Arc::clone(&packet_counts);
    let time_clone = Arc::clone(&last_reset);

    // Infinite loop.
    loop {
        // `rx.next()` gets the next packet, returning a `Result<&[u8], Error>`.
        // `&[u8]` is a slice of bytes (like Go’s `[]byte`).
        // `match` again for error handling.
        match rx.next() {
            // `Ok(packet)` is the success case, `packet` is the raw bytes.
            Ok(packet) => {
                // Try to parse the packet as an Ethernet frame.
                // `EthernetPacket::new` takes a `&[u8]` and returns an `Option<EthernetPacket>`.
                // `if let` is a shorthand for matching on `Option`—like Go’s `if val, ok := ...; ok`.
                // In Go, you’d use `gopacket.NewPacket` and check layers.
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    // TODO: parse srcIP from the IP header, instead of MAC address
                    let source = ethernet.get_source().to_string();

                    // Lock the shared state (like Go's mutex.Lock())
                    let mut counts = counts_clone.lock().unwrap(); // unwrap is like Go's panic on
                                                                   // error
                    let mut last_reset_time = time_clone.lock().unwrap();

                    // Reset counts every 10 seconds (rate limiting window)
                    if last_reset_time.elapsed() >= Duration::from_secs(10) {
                        counts.clear();
                        *last_reset_time = Instant::now();
                    }

                    // Increment packet count for this source
                    let count = counts.entry(source.clone()).or_insert(0);
                    *count += 1;

                    // Rate limiting logic: block if > 100 packets in 10s
                    if *count > 100 {
                        println!("Rate limiting exceeded for {}: {} packets", source, count);
                        // TODO: drop packets
                    } else {
                        println!("Packet from {}: total {}", source, count);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
                break;
            }
        }
    }
}
