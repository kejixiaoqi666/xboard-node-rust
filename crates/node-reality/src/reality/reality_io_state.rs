// Derived from cfal/shoes 60ed3838b346268615c81e4eace4e15e717da23e.
// Copyright (c) 2021-2023 Alex Lau; MIT license retained in this crate.
/// Represents the I/O state after processing packets
#[derive(Debug, Clone, Copy)]
pub struct RealityIoState {
    /// Number of plaintext bytes available to read
    plaintext_bytes_to_read: usize,
}

impl RealityIoState {
    /// Create a new RealityIoState
    pub fn new(plaintext_bytes_to_read: usize) -> Self {
        Self {
            plaintext_bytes_to_read,
        }
    }

    /// How many plaintext bytes could be obtained via Read without further I/O
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}
