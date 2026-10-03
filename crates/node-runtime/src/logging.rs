use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::Mutex,
};
pub fn emit(log: Option<&Log>, level: &str, message: &str) {
    if let Some(log) = log {
        log.write(level, message);
    } else {
        eprintln!("{message}");
    }
}
enum Sink {
    Stdout,
    Stderr,
    File(Mutex<File>),
}
pub struct Log {
    level: u8,
    sink: Sink,
    node: String,
}
impl Log {
    pub fn new(level: &str, output: &str, node: String) -> std::io::Result<Self> {
        let level = rank(level).ok_or_else(|| std::io::Error::other("invalid log level"))?;
        let sink = match output {
            "stdout" => Sink::Stdout,
            "stderr" | "" => Sink::Stderr,
            path => {
                let path = Path::new(path);
                if !path.is_absolute() {
                    return Err(std::io::Error::other("log path must be absolute"));
                }
                let mut options = OpenOptions::new();
                options.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                }
                Sink::File(Mutex::new(options.open(path)?))
            }
        };
        Ok(Self { level, sink, node })
    }
    pub fn write(&self, level: &str, message: &str) {
        if rank(level).is_none_or(|rank| rank < self.level) {
            return;
        }
        let line = serde_json::json!({"node":self.node,"level":level,"message":message})
            .to_string()
            + "\n";
        match &self.sink {
            Sink::Stdout => {
                let _ = std::io::stdout().lock().write_all(line.as_bytes());
            }
            Sink::Stderr => {
                let _ = std::io::stderr().lock().write_all(line.as_bytes());
            }
            Sink::File(file) => {
                if let Ok(mut file) = file.lock() {
                    let _ = file.write_all(line.as_bytes());
                }
            }
        }
    }
}
fn rank(value: &str) -> Option<u8> {
    match value {
        "debug" => Some(0),
        "info" => Some(1),
        "warn" => Some(2),
        "error" => Some(3),
        _ => None,
    }
}
