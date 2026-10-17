//! cargo build --release --target aarch64-unknown-linux-musl --example stk_probe
//! Queries/initializes STK only; never selects a service or supplies input.
#[path = "../src/stk/mod.rs"]
mod stk;
fn main() {
    let service = stk::StkService::new();
    let mut previous = String::new();
    for i in 0..12 {
        let (status, body) = service.request(if i == 0 { "menu" } else { "status" }, &[]);
        let value = serde_json::to_string(&body).unwrap_or_default();
        if value != previous {
            println!("HTTP {status} {value}");
            previous = value;
        }
        if status != 200 {
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
