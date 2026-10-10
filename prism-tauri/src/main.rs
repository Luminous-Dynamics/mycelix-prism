// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Prism — Tauri v2 desktop app.
//!
//! The Local Hub: direct URL fetching (no CORS), bundled search engine,
//! native filesystem access for persistent storage.
//!
//! Tauri commands are called from the Leptos WASM frontend via IPC.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use prism_common::{ContentZone, SafetyLevel};
use prism_dom::parse_html;
use prism_privacy::ConsentStore;
use prism_reflex::ReflexArc;
use prism_search::SearchEngine;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

/// Shared application state managed by Tauri.
struct PrismState {
    search: SearchEngine,
    reflex: ReflexArc,
    client: reqwest::Client,
}

/// Result of fetching and analyzing a URL.
#[derive(Serialize)]
struct FetchResult {
    html: String,
    title: String,
    zone: String,
    safety: String,
    threat_count: usize,
}

/// Search result for the frontend.
#[derive(Serialize)]
struct SearchResultJson {
    content: String,
    sources: Vec<String>,
    empirical_level: String,
    query_similarity: f32,
    author_reputation: f32,
    tags: Vec<String>,
    rank_score: f32,
}

/// Maximum decompressed response body accepted by the desktop fetch command.
///
/// This cap is checked against Content-Length when provided and against every
/// streamed chunk, so chunked or misleading-length responses cannot grow the
/// body buffer without bound. It is intentionally independent of the parser's
/// visible-text overload threshold, which runs only after the HTML is parsed.
const MAX_FETCH_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Append a response chunk only when it stays within the configured byte limit.
fn append_limited_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
) -> Result<(), &'static str> {
    if body.len().saturating_add(chunk.len()) > max_bytes {
        return Err("response exceeds configured byte limit");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Read an HTTP response with a hard body-size cap.
///
/// Checking Content-Length alone is insufficient because it can be missing or
/// incorrect. The chunk-by-chunk guard is the authoritative limit.
async fn read_limited_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, String> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes as u64 {
            return Err(format!(
                "Response exceeds the {max_bytes}-byte fetch limit"
            ));
        }
    }

    let initial_capacity = response
        .content_length()
        .map(|length| length.min(max_bytes as u64) as usize)
        .unwrap_or(0);
    let mut body = Vec::with_capacity(initial_capacity);

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("Read failed: {error}"))?
    {
        append_limited_chunk(&mut body, &chunk, max_bytes)
            .map_err(|_| format!("Response exceeds the {max_bytes}-byte fetch limit"))?;
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Fetch a URL directly (no CORS restrictions in native Tauri).
#[tauri::command]
async fn fetch_url(
    url: String,
    state: State<'_, Mutex<PrismState>>,
) -> Result<FetchResult, String> {
    // Clone the client before dropping the lock (reqwest::Client is cheaply cloneable)
    let client = {
        let s = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        s.client.clone()
    };

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Fetch failed: {}", e))?;

    let html = read_limited_response(response, MAX_FETCH_RESPONSE_BYTES).await?;

    // Sanitize
    let clean = ammonia::clean(&html);

    // Security analysis (re-acquire lock for reflex arc)
    let parsed_url = url::Url::parse(&url).map_err(|e| format!("Bad URL: {}", e))?;
    let dom = parse_html(&html);
    let title = dom.title().unwrap_or_else(|| "Untitled".to_string());

    let s = state.lock().map_err(|e| format!("Lock error: {}", e))?;
    let pre = s.reflex.pre_fetch(&parsed_url, false, false);
    let post = s.reflex.post_parse(&dom, &pre);
    let consent = ConsentStore::new();
    let zone = consent.resolve_zone(post.zone, parsed_url.host_str().unwrap_or(""));

    Ok(FetchResult {
        html: clean,
        title,
        zone: format!("{:?}", zone),
        safety: format!("{:?}", post.safety_level),
        threat_count: post.threats.len(),
    })
}

/// Perform epistemic search.
#[tauri::command]
fn search_claims(
    query: String,
    top_k: usize,
    state: State<'_, Mutex<PrismState>>,
) -> Result<Vec<SearchResultJson>, String> {
    let state = state.lock().map_err(|e| format!("Lock error: {}", e))?;
    let results = state.search.search(&query, top_k);

    Ok(results
        .into_iter()
        .map(|r| {
            let score = r.rank_score();
            SearchResultJson {
                content: r.content,
                sources: r.sources,
                empirical_level: format!("{:?}", r.empirical_level),
                query_similarity: r.query_similarity,
                author_reputation: r.author_reputation,
                tags: r.tags,
                rank_score: score,
            }
        })
        .collect())
}

/// Get claim count.
#[tauri::command]
fn claim_count(state: State<'_, Mutex<PrismState>>) -> Result<usize, String> {
    let state = state.lock().map_err(|e| format!("Lock error: {}", e))?;
    Ok(state.search.claim_count())
}

#[cfg(test)]
mod fetch_response_tests {
    use super::*;

    #[test]
    fn bounded_body_accepts_chunks_up_to_exact_limit() {
        let mut body = Vec::new();

        assert!(append_limited_chunk(&mut body, b"abc", 5).is_ok());
        assert!(append_limited_chunk(&mut body, b"de", 5).is_ok());

        assert_eq!(body, b"abcde");
    }

    #[test]
    fn bounded_body_rejects_over_limit_chunk_without_partial_append() {
        let mut body = b"abcd".to_vec();

        let result = append_limited_chunk(&mut body, b"ef", 5);

        assert_eq!(result, Err("response exceeds configured byte limit"));
        assert_eq!(body, b"abcd", "rejected chunks must not mutate the buffer");
    }

    #[test]
    fn bounded_body_rejects_later_chunk_after_exact_limit() {
        let mut body = Vec::new();

        assert!(append_limited_chunk(&mut body, b"1234", 4).is_ok());
        assert!(append_limited_chunk(&mut body, b"5", 4).is_err());
        assert_eq!(body, b"1234");
    }
}

fn main() {
    env_logger::init();

    // Build search index in a background thread to avoid blocking app launch.
    // The Mutex<PrismState> is populated immediately with an empty engine,
    // then swapped to the full engine once indexing completes.
    let prism_state = PrismState {
        search: SearchEngine::new(), // empty — loads fast
        reflex: ReflexArc::new(),
        client: reqwest::Client::builder()
            .user_agent("Prism/0.3 (Tauri; +https://mycelix.net)")
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("HTTP client"),
    };

    log::info!("Prism desktop starting (indexing in background)");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Mutex::new(prism_state))
        .invoke_handler(tauri::generate_handler![
            fetch_url,
            search_claims,
            claim_count,
        ])
        .setup(|app| {
            use tauri::Manager;

            // Background: load the search index without blocking the UI.
            // Use app.handle() which is 'static and cloneable.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let engine = SearchEngine::with_core_claims();
                let count = engine.claim_count();
                let state = handle.state::<Mutex<PrismState>>();
                if let Ok(mut s) = state.lock() {
                    s.search = engine;
                }
                log::info!("Search index loaded: {} claims", count);
            });

            // WebKitGTK layout fix (reduced delay)
            if let Some(window) = app.get_webview_window("main") {
                let w = window.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let _ = w.eval(
                        "document.documentElement.style.width='100vw';\
                         document.body.style.width='100vw';\
                         document.body.style.margin='0';\
                         document.body.style.overflow='hidden auto';\
                         window.dispatchEvent(new Event('resize'));",
                    );
                    if let Ok(size) = w.inner_size() {
                        let _ = w.set_size(tauri::Size::Physical(tauri::PhysicalSize::new(
                            size.width - 1,
                            size.height,
                        )));
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let _ = w.set_size(tauri::Size::Physical(tauri::PhysicalSize::new(
                            size.width,
                            size.height,
                        )));
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running Prism");
}
