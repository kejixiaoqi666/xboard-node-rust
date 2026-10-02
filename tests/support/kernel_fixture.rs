// A real child process fixture. It binds TCP and exits on malformed/failing input.
// Compiled by rustc using only std, so process tests work on Linux and Windows.
use std::{env, fs, net::TcpListener, thread, time::Duration};

fn port(text: &str) -> Option<u16> {
    for key in ["\"listen_port\":", "\"server_port\":"] {
        if let Some((_, tail)) = text.split_once(key) {
            let digits: String = tail.trim_start().chars().take_while(char::is_ascii_digit).collect();
            return digits.parse().ok();
        }
    }
    None
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.iter().any(|arg| arg == "assert-no-path") && env::var_os("PATH").is_some() { std::process::exit(97); }
    let text = fs::read_to_string(args.last().expect("config path")).expect("read config");
    if args.get(1).is_some_and(|arg| arg == "check") {
        if text.contains("\"name\":\"88\"") { std::process::exit(88); }
        if text.contains("\"name\":\"77\"") { thread::sleep(Duration::from_secs(60)); }
        assert!(port(&text).is_some());
        return;
    }
    if text.contains("\"name\":\"99\"") || text.contains("\"id\":99") { std::process::exit(99); }
    let listener = TcpListener::bind(("127.0.0.1", port(&text).expect("port"))).expect("bind");
    for stream in listener.incoming() { drop(stream.unwrap()); }
}
