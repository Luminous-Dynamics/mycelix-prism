// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Shared types for Prism.
//!
//! Prism is a consciousness-aware pure Rust browser with epistemic search,
//! powered by Symthaea.

use serde::{Deserialize, Serialize};

pub mod ssrf;

/// Privacy zone classification for web content.
///
/// Default is `Local`. Content must be explicitly upgraded to `Public`
/// via E3+/E4 epistemic classification or explicit user consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ContentZone {
    /// Never encoded, never shared. Banks, email, corporate portals.
    Private,
    /// HDC encoded for personal semantic memory. Never broadcast to DHT.
    #[default]
    Local,
    /// Encoded and offered to DHT with E/N/M classification.
    Public,
}

/// NRC-inspired safety level (Nuclear Regulatory Commission graduated response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyLevel {
    /// Normal operation.
    Green = 0,
    /// Heightened awareness — monitor, reduce learning rate.
    Yellow = 1,
    /// Active intervention — restrict output, reduce capabilities.
    Orange = 2,
    /// Emergency halt — block content, minimal response.
    Red = 3,
}

impl PartialOrd for SafetyLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SafetyLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

/// Threat categories detected by the reflex arc or immune system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// Prompt injection attempts ("ignore previous instructions").
    Adversarial,
    /// Harmful content ("exploit", "weapon").
    Harmful,
    /// Deception attempts ("pretend", "roleplay").
    Deceptive,
    /// Credential/boundary probing ("password", "SSN").
    Boundary,
    /// High non-alphanumeric ratio (< 30% alpha chars).
    Incoherent,
    /// Input exceeding size limits.
    Overload,
    /// Unclassified anomaly.
    Unknown,
}

// Re-export unified epistemic types from the shared crate.
pub use prism_epistemic_types::{
    ClaimType, EmpiricalLevel, EpistemicClassification, EpistemicConfidenceLevel,
    EpistemicEnvelope, MaterialityLevel, NormativeLevel, UnifiedClaim,
};

/// A search result from the epistemic knowledge engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResult {
    /// The claim text.
    pub content: String,
    /// Original source URL(s).
    pub sources: Vec<String>,
    /// Empirical evidence level (E0-E4).
    pub empirical_level: EmpiricalLevel,
    /// Normative consensus level (N0-N3).
    pub normative_level: NormativeLevel,
    /// Materiality / real-world impact (M0-M3).
    pub materiality_level: MaterialityLevel,
    /// Normalized HDC similarity signal (0.0-1.0), not a calibrated probability.
    /// None means this result did not have a measured local similarity score.
    pub query_similarity: Option<f32>,
    /// Verified author reputation (0.0-1.0), if available from a trusted profile.
    /// None means reputation is unknown; missing provenance is not zero reputation.
    pub author_reputation: Option<f32>,
    /// Age in days since a verified creation/retrieval timestamp.
    /// None means the result's age is unknown.
    pub age_days: Option<u32>,
    /// Tags for categorization.
    pub tags: Vec<String>,
}

impl SearchResult {
    /// Composite ranking score from available evidence.
    ///
    /// Unknown metadata contributes neither a fabricated value nor an implicit
    /// penalty. The remaining component weights are normalized to sum to one.
    /// This is a ranking heuristic, not a calibrated probability of relevance.
    pub fn rank_score(&self) -> f32 {
        let mut weighted_score = 0.3 * self.empirical_level.as_f32();
        let mut total_weight = 0.3_f32;

        if let Some(similarity) = self.query_similarity {
            weighted_score += 0.4 * similarity.clamp(0.0, 1.0);
            total_weight += 0.4;
        }

        if let Some(reputation) = self.author_reputation {
            weighted_score += 0.2 * reputation.clamp(0.0, 1.0);
            total_weight += 0.2;
        }

        if let Some(age_days) = self.age_days {
            let freshness = 1.0 / (1.0 + age_days as f32 / 365.0);
            weighted_score += 0.1 * freshness;
            total_weight += 0.1;
        }

        (weighted_score / total_weight).clamp(0.0, 1.0)
    }
}

/// Node participation tier in the P2P search network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeTier {
    /// Browser users. Query + submit. No persistent storage for others.
    Light,
    /// Community operators. Serve LSH shards. TEND-incentivized. K-vector >= 0.4.
    Relay,
    /// Institutions/dedicated. Full index replicas. K-vector >= 0.6.
    Archive,
}

/// Unique identifier for a browser tab.
pub type TabId = u32;

/// Unique identifier for a search query.
pub type QueryId = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_zone_default_is_local() {
        assert_eq!(ContentZone::default(), ContentZone::Local);
    }

    #[test]
    fn safety_level_ordering() {
        assert!(SafetyLevel::Green < SafetyLevel::Yellow);
        assert!(SafetyLevel::Yellow < SafetyLevel::Orange);
        assert!(SafetyLevel::Orange < SafetyLevel::Red);
        assert!(SafetyLevel::Green < SafetyLevel::Red);
    }

    #[test]
    fn safety_level_max() {
        assert_eq!(
            SafetyLevel::Green.max(SafetyLevel::Orange),
            SafetyLevel::Orange
        );
        assert_eq!(SafetyLevel::Red.max(SafetyLevel::Yellow), SafetyLevel::Red);
    }

    #[test]
    fn rank_score_weights() {
        let result = SearchResult {
            content: "test".into(),
            sources: vec![],
            empirical_level: EmpiricalLevel::E4,
            normative_level: NormativeLevel::N1,
            materiality_level: MaterialityLevel::M2,
            query_similarity: Some(1.0),
            author_reputation: Some(1.0),
            age_days: Some(0),
            tags: vec![],
        };
        // Max everything: 0.4*1.0 + 0.3*1.0 + 0.2*1.0 + 0.1*1.0 = 1.0
        let score = result.rank_score();
        assert!(
            (score - 1.0).abs() < 0.01,
            "max score should be ~1.0, got {}",
            score
        );
    }

    #[test]
    fn rank_score_zero() {
        let result = SearchResult {
            content: "test".into(),
            sources: vec![],
            empirical_level: EmpiricalLevel::E0,
            normative_level: NormativeLevel::N0,
            materiality_level: MaterialityLevel::M0,
            query_similarity: Some(0.0),
            author_reputation: Some(0.0),
            age_days: Some(365_000), // very old
            tags: vec![],
        };
        let score = result.rank_score();
        assert!(score < 0.01, "min score should be near 0, got {}", score);
    }

    #[test]
    fn rank_score_freshness_decay() {
        let fresh = SearchResult {
            content: "test".into(),
            sources: vec![],
            empirical_level: EmpiricalLevel::E2,
            normative_level: NormativeLevel::N1,
            materiality_level: MaterialityLevel::M1,
            query_similarity: Some(0.5),
            author_reputation: Some(0.5),
            age_days: Some(0),
            tags: vec![],
        };
        let mut stale = fresh.clone();
        stale.age_days = Some(3650); // 10 years
        assert!(fresh.rank_score() > stale.rank_score());
    }

    #[test]
    fn search_result_serde_roundtrip() {
        let result = SearchResult {
            content: "Ocean acidification reduces shell formation".into(),
            sources: vec!["NOAA".into(), "doi:10.1234".into()],
            empirical_level: EmpiricalLevel::E3,
            normative_level: NormativeLevel::N2,
            materiality_level: MaterialityLevel::M3,
            query_similarity: Some(0.87),
            author_reputation: Some(0.92),
            age_days: Some(42),
            tags: vec!["climate".into(), "ocean".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: SearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    #[test]
    fn missing_provenance_is_unknown_not_fabricated() {
        let result = SearchResult {
            content: "external claim without verified metadata".into(),
            sources: vec![],
            empirical_level: EmpiricalLevel::E2,
            normative_level: NormativeLevel::N1,
            materiality_level: MaterialityLevel::M1,
            query_similarity: None,
            author_reputation: None,
            age_days: None,
            tags: vec![],
        };

        let score = result.rank_score();
        assert!(score.is_finite());
        assert!((0.0..=1.0).contains(&score));
        assert_eq!(result.query_similarity, None);
        assert_eq!(result.author_reputation, None);
        assert_eq!(result.age_days, None);
    }

    #[test]
    fn content_zone_serde_roundtrip() {
        for zone in [
            ContentZone::Private,
            ContentZone::Local,
            ContentZone::Public,
        ] {
            let json = serde_json::to_string(&zone).unwrap();
            let restored: ContentZone = serde_json::from_str(&json).unwrap();
            assert_eq!(zone, restored);
        }
    }

    #[test]
    fn safety_level_serde_roundtrip() {
        for level in [
            SafetyLevel::Green,
            SafetyLevel::Yellow,
            SafetyLevel::Orange,
            SafetyLevel::Red,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let restored: SafetyLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, restored);
        }
    }

    #[test]
    fn threat_type_variants_are_distinct() {
        let threats = [
            ThreatType::Adversarial,
            ThreatType::Harmful,
            ThreatType::Deceptive,
            ThreatType::Boundary,
            ThreatType::Incoherent,
            ThreatType::Overload,
            ThreatType::Unknown,
        ];
        // All 7 variants should be unique
        let set: std::collections::HashSet<_> = threats.iter().collect();
        assert_eq!(set.len(), 7);
    }

    #[test]
    fn node_tier_serde_roundtrip() {
        for tier in [NodeTier::Light, NodeTier::Relay, NodeTier::Archive] {
            let json = serde_json::to_string(&tier).unwrap();
            let restored: NodeTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, restored);
        }
    }
}
