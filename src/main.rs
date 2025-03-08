// Rust uses `use` to import modules.
// `pnet::datalink` is a module from the `pnet` crate (library).
// The curly braces `{}` let us import specific items from `datalink`.
// `self` means we also import the `datalink` module itself.
use pnet::datalink::{self, NetworkInterface};
// In this case we import the `Packet` trait from `pnet::packet`.
// Traits in Rust are like Go interfaces.
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
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

    // Find the first active, non-loopback interface (for simplicity).
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
        .find(|iface| iface.is_ip() && !iface.is_loopback())
        // `expect` unwraps the `Option`, panicking with a message if `None`.
        // In Go, we'd panic manually: `if iface == nil { panic("no interface") }`.
        .expect("No suitable network interface found");
    
    // `println!` is a macro, like Go's `fmt.Println`.
    // `{}` is a placeholder, filled by `interface.name`.
    println!("Using interface: {}", interface.name);

    // Open a packet capture channel on the interface.
    // `&interface` passes a reference (borrow), not the value itself.
    // `Default::default()` gives default config options, like Go's zero values.
    // `datalink::channel` returns a `Result`, Rust's way of handling errors (like Go's `value,
    // err`).
    // `match` is like Go's `switch`, but more powerful, it pattern-matches on the `Result`.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
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
}
