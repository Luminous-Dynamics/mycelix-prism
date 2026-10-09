//! # Prism Kernel Protocol
//! Inter-process wire protocol definitions for communication between the Prism
//! process broker (`prism-shell`) and the kernel security authority service.

use serde::{Deserialize, Serialize};

/// Message frame passed over the security IPC socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KernelFrame {
    /// Ping request to verify broker/kernel liveness.
    Ping,
    /// Pong response from kernel authority.
    Pong,
    /// Landlock sandbox policy configuration update.
    SetSandboxPolicy {
        read_paths: Vec<String>,
        write_paths: Vec<String>,
    },
    /// Status response from kernel authority.
    StatusResponse {
        active_sandboxes: usize,
        seccomp_enforced: bool,
    },
}
