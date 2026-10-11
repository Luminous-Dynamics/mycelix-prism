// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Shared resource limits for Prism's untrusted HTTP request boundary.

/// Maximum URI path-plus-query accepted by Prism's HTTP handlers.
///
/// This is an application-level cap: the HTTP server has already parsed the
/// request target when this middleware executes, but oversized targets are
/// rejected before Axum query extractors and upstream provider calls run.
pub const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;
