// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Operation-scoped outbound consent.
//!
//! A hostname preference is not an authorization grant. This module binds an
//! explicit grant to one destination, operation, content scope, purpose, and
//! policy version. Private content is never exportable through this API.
//!
//! The final synchronous commit/enqueue closure runs while the authority lock
//! is held. Revocation uses the same lock, so a revocation acknowledgement is
//! ordered after any commit closure that already started and before every
//! later commit closure. The closure must be the short, local irreversible
//! commit boundary (for example, an atomic queue insertion), not a long-running
//! network transfer. A downstream sender must revalidate at its own send
//! boundary if queued work can outlive this one.
//!
//! Time is injected to make policy decisions deterministic. Production callers
//! must supply a trusted clock reading and pass None on clock failure. This
//! implementation fails closed on a backwards timestamp, but cannot establish
//! that the caller's clock is trustworthy.

use super::canonical_domain;
use prism_common::ContentZone;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

const MAX_ID_BYTES: usize = 128;
const MAX_SCOPE_BYTES: usize = 512;
const MAX_PURPOSE_BYTES: usize = 256;
const MAX_POLICY_VERSION_BYTES: usize = 128;
const MAX_CHOICE_RECEIPT_BYTES: usize = 256;

/// A specific outbound action that a user can authorize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundOperation {
    ShareToDht,
    SendToRecipient,
    ExportToFile,
    SubmitForm,
}

/// Durable consent metadata. Callers must pass grants through
/// GrantAuthority::issue; deserialization alone never makes a grant active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentGrant {
    pub id: String,
    /// Exact DNS hostname, not a URL, origin, wildcard, or suffix.
    pub destination: String,
    pub operation: OutboundOperation,
    /// Privacy classification of the data authorized by this grant.
    pub zone: ContentZone,
    /// Stable data/sensitivity scope such as a content ID or named data class.
    pub content_scope: String,
    pub purpose: String,
    pub policy_version: String,
    /// Opaque reference to integrity-protected evidence of the user's explicit choice.
    pub user_choice_receipt: String,
    /// Unix epoch milliseconds. Validity interval is [issued_at, expires_at).
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

/// The action attempting to cross the outbound boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub grant_id: String,
    pub destination: String,
    pub operation: OutboundOperation,
    pub content_scope: String,
    pub purpose: String,
    pub policy_version: String,
    pub zone: ContentZone,
}

/// A permit is an in-memory capability for exactly one request binding.
/// Its fields are private and it cannot be constructed by deserializing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPermit {
    binding: RequestBinding,
    grant_epoch: u64,
}

impl GrantPermit {
    pub fn grant_id(&self) -> &str {
        &self.binding.grant_id
    }

    /// Monotonic epoch observed when this permit was issued.
    pub fn grant_epoch(&self) -> u64 {
        self.grant_epoch
    }
}

/// Receipt returned after revocation has serialized against commit closures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationReceipt {
    pub grant_id: String,
    pub grant_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantValidationError {
    InvalidIdentifier,
    InvalidDestination,
    InvalidContentScope,
    InvalidPurpose,
    InvalidPolicyVersion,
    InvalidChoiceReceipt,
    PrivateDataGrant,
    InvalidTimeWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    InvalidGrant(GrantValidationError),
    DuplicateGrantId,
    DuplicateChoiceReceipt,
    MissingGrant,
    PolicyVersionMismatch,
    PolicyEpochExhausted,
    AuthorityUnavailable,
    EpochExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    PrivateData,
    InvalidDestination,
    InvalidRequest,
    MissingGrant,
    Revoked,
    AlreadyConsumed,
    DestinationMismatch,
    OperationMismatch,
    ScopeMismatch,
    ZoneMismatch,
    PurposeMismatch,
    PolicyVersionMismatch,
    NotYetValid,
    Expired,
    ClockUnavailable,
    ClockRollback,
    StalePermit,
    AuthorityUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestBinding {
    grant_id: String,
    destination: String,
    operation: OutboundOperation,
    content_scope: String,
    purpose: String,
    policy_version: String,
    zone: ContentZone,
}

struct GrantRecord {
    grant: ConsentGrant,
    /// Starts at 1 and advances on revocation; old permits never refresh.
    epoch: u64,
    revoked: bool,
    consumed: bool,
    /// Authority policy generation when this grant was issued.
    policy_epoch: u64,
}

#[derive(Default)]
struct AuthorityState {
    grants: HashMap<String, GrantRecord>,
    last_observed_unix_ms: Option<u64>,
    /// Authoritative active policy version; never taken from the request.
    current_policy_version: String,
    /// Monotonic policy generation prevents version-string rollback reactivation.
    current_policy_epoch: u64,
}

/// Thread-safe, fail-closed grant authority.
pub struct GrantAuthority {
    state: Mutex<AuthorityState>,
}

impl GrantAuthority {
    /// Construct with the policy version currently enforced by this authority.
    pub fn new(current_policy_version: &str) -> Result<Self, GrantValidationError> {
        if !valid_atom(current_policy_version, MAX_POLICY_VERSION_BYTES) {
            return Err(GrantValidationError::InvalidPolicyVersion);
        }
        Ok(Self {
            state: Mutex::new(AuthorityState {
                current_policy_version: current_policy_version.to_owned(),
                current_policy_epoch: 1,
                ..AuthorityState::default()
            }),
        })
    }

    /// Rotate the authoritative policy version. Grants issued under older
    /// versions become unusable immediately; callers must obtain fresh consent.
    pub fn set_current_policy_version(&self, version: &str) -> Result<(), GrantError> {
        if !valid_atom(version, MAX_POLICY_VERSION_BYTES) {
            return Err(GrantError::InvalidGrant(
                GrantValidationError::InvalidPolicyVersion,
            ));
        }
        let mut state = self.lock_state().map_err(|_| GrantError::AuthorityUnavailable)?;
        if state.current_policy_version == version {
            return Ok(());
        }
        let next_epoch = state
            .current_policy_epoch
            .checked_add(1)
            .ok_or(GrantError::PolicyEpochExhausted)?;
        state.current_policy_version = version.to_owned();
        state.current_policy_epoch = next_epoch;
        Ok(())
    }

    /// Validate and register a grant. IDs are never reused, including after
    /// revocation, preventing a queued permit from referring to a replacement.
    pub fn issue(&self, mut grant: ConsentGrant) -> Result<(), GrantError> {
        validate_grant(&grant).map_err(GrantError::InvalidGrant)?;
        grant.destination = canonical_domain(&grant.destination)
            .ok_or(GrantError::InvalidGrant(
                GrantValidationError::InvalidDestination,
            ))?;

        let mut state = self.lock_state().map_err(|_| GrantError::AuthorityUnavailable)?;
        if grant.policy_version != state.current_policy_version {
            return Err(GrantError::PolicyVersionMismatch);
        }
        if state.grants.contains_key(&grant.id) {
            return Err(GrantError::DuplicateGrantId);
        }
        if state
            .grants
            .values()
            .any(|record| record.grant.user_choice_receipt == grant.user_choice_receipt)
        {
            return Err(GrantError::DuplicateChoiceReceipt);
        }

        let issued_policy_epoch = state.current_policy_epoch;
        state.grants.insert(
            grant.id.clone(),
            GrantRecord {
                grant,
                epoch: 1,
                revoked: false,
                consumed: false,
                policy_epoch: issued_policy_epoch,
            },
        );
        Ok(())
    }

    /// Evaluate one request. This creates no reusable bearer token outside
    /// this process; the returned permit is bound to all request attributes.
    pub fn authorize(
        &self,
        request: &OutboundRequest,
        now_unix_ms: Option<u64>,
    ) -> Result<GrantPermit, DenialReason> {
        let binding = binding_for(request)?;
        let mut state = self.lock_state().map_err(|_| DenialReason::AuthorityUnavailable)?;
        let epoch = validate_locked(&mut state, &binding, now_unix_ms)?;
        Ok(GrantPermit {
            binding,
            grant_epoch: epoch,
        })
    }

    /// Revalidate at the final local commit boundary and execute the closure
    /// while holding the same lock used by revoke().
    ///
    /// The closure must be short, synchronous, and non-reentrant with respect
    /// to this authority. If it panics, the mutex is poisoned and future
    /// authorization/revocation calls fail closed. Return values from the
    /// closure are passed through unchanged.
    pub fn commit_with<T, F>(
        &self,
        permit: &GrantPermit,
        request: &OutboundRequest,
        now_unix_ms: Option<u64>,
        commit: F,
    ) -> Result<T, DenialReason>
    where
        F: FnOnce() -> T,
    {
        let binding = binding_for(request)?;
        if binding != permit.binding {
            return Err(DenialReason::StalePermit);
        }

        let mut state = self.lock_state().map_err(|_| DenialReason::AuthorityUnavailable)?;
        let current_epoch = validate_locked(&mut state, &binding, now_unix_ms)?;
        if current_epoch != permit.grant_epoch {
            return Err(DenialReason::StalePermit);
        }

        // Each explicit consent receipt authorizes one commit only. Consume the
        // grant before calling user code so panic/re-entry cannot replay it.
        let record = state
            .grants
            .get_mut(&binding.grant_id)
            .ok_or(DenialReason::MissingGrant)?;
        if record.consumed {
            return Err(DenialReason::AlreadyConsumed);
        }
        record.consumed = true;

        // Linearization boundary: revoke() cannot acknowledge while this
        // closure is in progress, and no later closure can pass after revoke.
        Ok(commit())
    }

    /// Revoke one grant. This call returns only after any earlier commit
    /// closure releases the authority lock. Repeated revocation is idempotent.
    pub fn revoke(&self, grant_id: &str) -> Result<RevocationReceipt, GrantError> {
        if !valid_atom(grant_id, MAX_ID_BYTES) {
            return Err(GrantError::MissingGrant);
        }
        let mut state = self.lock_state().map_err(|_| GrantError::AuthorityUnavailable)?;
        let record = state
            .grants
            .get_mut(grant_id)
            .ok_or(GrantError::MissingGrant)?;

        if !record.revoked {
            // Mark revoked first so even the practically unreachable overflow
            // path fails closed rather than leaving the grant usable.
            record.revoked = true;
            record.epoch = record
                .epoch
                .checked_add(1)
                .ok_or(GrantError::EpochExhausted)?;
        }

        Ok(RevocationReceipt {
            grant_id: grant_id.to_owned(),
            grant_epoch: record.epoch,
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AuthorityState>, ()> {
        self.state.lock().map_err(|_| ())
    }
}

fn validate_grant(grant: &ConsentGrant) -> Result<(), GrantValidationError> {
    if !valid_atom(&grant.id, MAX_ID_BYTES) {
        return Err(GrantValidationError::InvalidIdentifier);
    }
    if canonical_domain(&grant.destination).is_none() {
        return Err(GrantValidationError::InvalidDestination);
    }
    if grant.zone == ContentZone::Private {
        return Err(GrantValidationError::PrivateDataGrant);
    }
    if !valid_atom(&grant.content_scope, MAX_SCOPE_BYTES) {
        return Err(GrantValidationError::InvalidContentScope);
    }
    if !valid_atom(&grant.purpose, MAX_PURPOSE_BYTES) {
        return Err(GrantValidationError::InvalidPurpose);
    }
    if !valid_atom(&grant.policy_version, MAX_POLICY_VERSION_BYTES) {
        return Err(GrantValidationError::InvalidPolicyVersion);
    }
    if !valid_atom(&grant.user_choice_receipt, MAX_CHOICE_RECEIPT_BYTES) {
        return Err(GrantValidationError::InvalidChoiceReceipt);
    }
    if grant.expires_at_unix_ms <= grant.issued_at_unix_ms {
        return Err(GrantValidationError::InvalidTimeWindow);
    }
    Ok(())
}

fn valid_atom(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn binding_for(request: &OutboundRequest) -> Result<RequestBinding, DenialReason> {
    // Explicit privacy classification always dominates consent.
    if request.zone == ContentZone::Private {
        return Err(DenialReason::PrivateData);
    }
    let destination =
        canonical_domain(&request.destination).ok_or(DenialReason::InvalidDestination)?;
    if !valid_atom(&request.grant_id, MAX_ID_BYTES)
        || !valid_atom(&request.content_scope, MAX_SCOPE_BYTES)
        || !valid_atom(&request.purpose, MAX_PURPOSE_BYTES)
        || !valid_atom(&request.policy_version, MAX_POLICY_VERSION_BYTES)
    {
        return Err(DenialReason::InvalidRequest);
    }

    Ok(RequestBinding {
        grant_id: request.grant_id.clone(),
        destination,
        operation: request.operation,
        content_scope: request.content_scope.clone(),
        purpose: request.purpose.clone(),
        policy_version: request.policy_version.clone(),
        zone: request.zone,
    })
}

fn validate_locked(
    state: &mut AuthorityState,
    binding: &RequestBinding,
    now_unix_ms: Option<u64>,
) -> Result<u64, DenialReason> {
    let now = now_unix_ms.ok_or(DenialReason::ClockUnavailable)?;
    if state
        .last_observed_unix_ms
        .is_some_and(|previous| now < previous)
    {
        return Err(DenialReason::ClockRollback);
    }
    state.last_observed_unix_ms = Some(now);

    let record = state
        .grants
        .get(&binding.grant_id)
        .ok_or(DenialReason::MissingGrant)?;
    if record.revoked {
        return Err(DenialReason::Revoked);
    }
    if record.consumed {
        return Err(DenialReason::AlreadyConsumed);
    }

    let grant = &record.grant;
    if record.policy_epoch != state.current_policy_epoch
        || grant.policy_version != state.current_policy_version
    {
        return Err(DenialReason::PolicyVersionMismatch);
    }
    if grant.destination != binding.destination {
        return Err(DenialReason::DestinationMismatch);
    }
    if grant.operation != binding.operation {
        return Err(DenialReason::OperationMismatch);
    }
    if grant.content_scope != binding.content_scope {
        return Err(DenialReason::ScopeMismatch);
    }
    if grant.zone != binding.zone {
        return Err(DenialReason::ZoneMismatch);
    }
    if grant.purpose != binding.purpose {
        return Err(DenialReason::PurposeMismatch);
    }
    if grant.policy_version != binding.policy_version {
        return Err(DenialReason::PolicyVersionMismatch);
    }
    if now < grant.issued_at_unix_ms {
        return Err(DenialReason::NotYetValid);
    }
    if now >= grant.expires_at_unix_ms {
        return Err(DenialReason::Expired);
    }

    Ok(record.epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    fn sample_grant(id: &str) -> ConsentGrant {
        ConsentGrant {
            id: id.into(),
            destination: "Example.COM.".into(),
            operation: OutboundOperation::SendToRecipient,
            zone: ContentZone::Local,
            content_scope: "document:case-17".into(),
            purpose: "deliver-user-requested-document".into(),
            policy_version: "prism-policy-v1".into(),
            user_choice_receipt: "choice-receipt-17".into(),
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 200,
        }
    }

    fn sample_request(zone: ContentZone) -> OutboundRequest {
        OutboundRequest {
            grant_id: "grant-1".into(),
            destination: "example.com".into(),
            operation: OutboundOperation::SendToRecipient,
            content_scope: "document:case-17".into(),
            purpose: "deliver-user-requested-document".into(),
            policy_version: "prism-policy-v1".into(),
            zone,
        }
    }

    fn sample_authority() -> GrantAuthority {
        let authority = GrantAuthority::new("prism-policy-v1").unwrap();
        authority.issue(sample_grant("grant-1")).unwrap();
        authority
    }

    #[test]
    fn exact_scoped_grant_can_commit_once() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        let permit = authority.authorize(&request, Some(100)).unwrap();
        assert_eq!(permit.grant_id(), "grant-1");
        assert_eq!(permit.grant_epoch(), 1);

        let result = authority
            .commit_with(&permit, &request, Some(101), || "committed")
            .unwrap();
        assert_eq!(result, "committed");
        assert_eq!(
            authority.authorize(&request, Some(102)),
            Err(DenialReason::AlreadyConsumed),
            "the same user choice must not authorize a second commit"
        );
    }

    #[test]
    fn private_content_never_exports_even_with_matching_grant() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Private);
        assert_eq!(
            authority.authorize(&request, Some(100)),
            Err(DenialReason::PrivateData)
        );
    }

    #[test]
    fn each_binding_dimension_is_authority_relevant() {
        let authority = sample_authority();
        let base = sample_request(ContentZone::Local);
        let cases = [
            (OutboundRequest { destination: "sub.example.com".into(), ..base.clone() }, DenialReason::DestinationMismatch),
            (OutboundRequest { operation: OutboundOperation::ExportToFile, ..base.clone() }, DenialReason::OperationMismatch),
            (OutboundRequest { content_scope: "document:other".into(), ..base.clone() }, DenialReason::ScopeMismatch),
            (OutboundRequest { zone: ContentZone::Public, ..base.clone() }, DenialReason::ZoneMismatch),
            (OutboundRequest { purpose: "analytics".into(), ..base.clone() }, DenialReason::PurposeMismatch),
            (OutboundRequest { policy_version: "prism-policy-v2".into(), ..base.clone() }, DenialReason::PolicyVersionMismatch),
        ];

        for (request, expected) in cases {
            assert_eq!(authority.authorize(&request, Some(100)), Err(expected));
        }
    }

    #[test]
    fn hostname_case_and_root_dot_do_not_change_exact_destination() {
        let authority = sample_authority();
        let mut request = sample_request(ContentZone::Local);
        request.destination = "EXAMPLE.COM.".into();
        assert!(authority.authorize(&request, Some(100)).is_ok());

        request.destination = "example.com.evil.test".into();
        assert_eq!(
            authority.authorize(&request, Some(101)),
            Err(DenialReason::DestinationMismatch)
        );
    }

    #[test]
    fn revocation_invalidates_a_queued_permit_before_commit() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        let permit = authority.authorize(&request, Some(100)).unwrap();
        let receipt = authority.revoke("grant-1").unwrap();
        assert_eq!(receipt.grant_epoch, 2);

        let mut ran = false;
        assert_eq!(
            authority.commit_with(&permit, &request, Some(101), || ran = true),
            Err(DenialReason::Revoked)
        );
        assert!(!ran, "revoked work must not run its commit closure");
    }

    #[test]
    fn expiry_is_exclusive_and_issue_time_is_inclusive() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        assert_eq!(
            authority.authorize(&request, Some(99)),
            Err(DenialReason::NotYetValid)
        );
        assert_eq!(
            authority.authorize(&request, Some(200)),
            Err(DenialReason::Expired)
        );
    }

    #[test]
    fn missing_clock_and_clock_rollback_fail_closed() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        assert_eq!(
            authority.authorize(&request, None),
            Err(DenialReason::ClockUnavailable)
        );

        assert!(authority.authorize(&request, Some(100)).is_ok());
        assert_eq!(
            authority.authorize(&request, Some(99)),
            Err(DenialReason::ClockRollback)
        );
    }

    #[test]
    fn policy_rotation_invalidates_old_grants_and_permits() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        let permit = authority.authorize(&request, Some(100)).unwrap();

        authority.set_current_policy_version("prism-policy-v2").unwrap();
        assert_eq!(
            authority.commit_with(&permit, &request, Some(101), || ()),
            Err(DenialReason::PolicyVersionMismatch)
        );

        let updated_request = OutboundRequest {
            policy_version: "prism-policy-v2".into(),
            ..request
        };
        assert_eq!(
            authority.authorize(&updated_request, Some(102)),
            Err(DenialReason::PolicyVersionMismatch),
            "a caller cannot make an old grant current by changing its request version"
        );

        assert_eq!(
            authority.issue(sample_grant("stale-policy-grant")),
            Err(GrantError::PolicyVersionMismatch)
        );
    }

    #[test]
    fn policy_version_rollback_does_not_reactivate_old_grants() {
        let authority = sample_authority();
        let request = sample_request(ContentZone::Local);
        let permit = authority.authorize(&request, Some(100)).unwrap();

        authority.set_current_policy_version("prism-policy-v2").unwrap();
        authority.set_current_policy_version("prism-policy-v1").unwrap();

        assert_eq!(
            authority.authorize(&request, Some(101)),
            Err(DenialReason::PolicyVersionMismatch),
            "returning to an old version label must not revive the old grant"
        );
        assert_eq!(
            authority.commit_with(&permit, &request, Some(102), || ()),
            Err(DenialReason::PolicyVersionMismatch)
        );
    }

    #[test]
    fn malformed_grants_are_rejected_without_registration() {
        let authority = GrantAuthority::new("prism-policy-v1").unwrap();
        authority.issue(sample_grant("existing-grant")).unwrap();

        let mut invalid_host = sample_grant("bad-host");
        invalid_host.destination = "example.com/path".into();
        assert_eq!(
            authority.issue(invalid_host),
            Err(GrantError::InvalidGrant(
                GrantValidationError::InvalidDestination
            ))
        );

        let mut invalid_scope = sample_grant("bad-scope");
        invalid_scope.content_scope = "  ".into();
        assert_eq!(
            authority.issue(invalid_scope),
            Err(GrantError::InvalidGrant(
                GrantValidationError::InvalidContentScope
            ))
        );

        let mut reused_receipt = sample_grant("second-grant");
        reused_receipt.destination = "elsewhere.example".into();
        assert_eq!(
            authority.issue(reused_receipt),
            Err(GrantError::DuplicateChoiceReceipt)
        );

        let mut invalid_receipt = sample_grant("bad-receipt");
        invalid_receipt.user_choice_receipt.clear();
        assert_eq!(
            authority.issue(invalid_receipt),
            Err(GrantError::InvalidGrant(
                GrantValidationError::InvalidChoiceReceipt
            ))
        );

        let mut invalid_window = sample_grant("bad-window");
        invalid_window.expires_at_unix_ms = invalid_window.issued_at_unix_ms;
        assert_eq!(
            authority.issue(invalid_window),
            Err(GrantError::InvalidGrant(
                GrantValidationError::InvalidTimeWindow
            ))
        );
    }

    #[test]
    fn duplicate_ids_cannot_replace_or_resurrect_a_grant() {
        let authority = sample_authority();
        authority.revoke("grant-1").unwrap();
        assert_eq!(
            authority.issue(sample_grant("grant-1")),
            Err(GrantError::DuplicateGrantId)
        );
    }

    #[test]
    fn changed_request_cannot_reuse_permit() {
        let authority = sample_authority();
        let original = sample_request(ContentZone::Local);
        let permit = authority.authorize(&original, Some(100)).unwrap();
        let changed = OutboundRequest {
            purpose: "different-purpose".into(),
            ..original
        };

        assert_eq!(
            authority.commit_with(&permit, &changed, Some(101), || ()),
            Err(DenialReason::StalePermit)
        );
    }

    #[test]
    fn revocation_acknowledgement_waits_for_commit_boundary() {
        let authority = Arc::new(sample_authority());
        let request = sample_request(ContentZone::Local);
        let permit = authority.authorize(&request, Some(100)).unwrap();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (effect_tx, effect_rx) = mpsc::channel::<()>();
        let worker_authority = Arc::clone(&authority);

        let worker = thread::spawn(move || {
            worker_authority.commit_with(&permit, &request, Some(101), || {
                effect_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });

        effect_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("commit closure did not start");
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (ack_tx, ack_rx) = mpsc::channel();
        let revoker_authority = Arc::clone(&authority);
        let revoker = thread::spawn(move || {
            started_tx.send(()).unwrap();
            ack_tx.send(revoker_authority.revoke("grant-1")).unwrap();
        });

        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("revocation thread did not start");
        assert!(
            ack_rx.try_recv().is_err(),
            "revocation cannot be acknowledged during an active commit closure"
        );

        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        let receipt = ack_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("revocation did not acknowledge after commit completed")
            .unwrap();
        assert_eq!(receipt.grant_epoch, 2);
        revoker.join().unwrap();
    }
}
