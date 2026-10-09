// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Incident-policy history types.
//!
//! Minimal stub — full cryptographic verification and append-only chain
//! implementation is planned.

use serde::{Deserialize, Serialize};

/// A signed transition between incident-policy states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedIncidentPolicyTransition {
    /// Arbitrary payload bytes (policy diff or full policy document).
    pub payload: serde_json::Value,
    /// Hex-encoded Ed25519 signature over the canonical payload.
    pub signature: String,
    /// Hex-encoded Ed25519 public key of the signing authority.
    pub signing_key: String,
}

/// An append-only, hash-chained record of incident-policy transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPolicyHistory {
    /// BLAKE3 hash over the entire ordered history.
    pub history_root_blake3: [u8; 32],
    /// The genesis policy document (raw bytes stored as base64 in JSON).
    #[serde(with = "serde_bytes_base64")]
    pub genesis_policy: Vec<u8>,
    /// Ordered list of signed transitions applied after genesis.
    pub transitions: Vec<SignedIncidentPolicyTransition>,
}

impl IncidentPolicyHistory {
    /// Construct a new history from a genesis policy and a list of transitions.
    ///
    /// The `history_root_blake3` is computed as BLAKE3 over
    /// `genesis_policy || each transition's canonical JSON`.
    pub fn new(
        genesis_bytes: &[u8],
        transitions: Vec<SignedIncidentPolicyTransition>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(genesis_bytes);
        for transition in &transitions {
            let canonical = serde_json::to_vec(transition)?;
            hasher.update(&canonical);
        }
        let root = hasher.finalize();
        Ok(Self {
            history_root_blake3: *root.as_bytes(),
            genesis_policy: genesis_bytes.to_vec(),
            transitions,
        })
    }
}

/// Serde helper: serialize/deserialize `Vec<u8>` as base64.
mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        // Simple hex encoding as a stand-in until a base64 dep is wired in.
        s.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd hex length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}
