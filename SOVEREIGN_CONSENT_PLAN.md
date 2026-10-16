# Sovereign-Aware Privacy Policy Integration (Proposal — Trust Is Not Consent)

## Status

This proposal is not authorization to make sharing decisions from reputation, competence, identity assurance, or sovereign-profile scores. Any earlier example that elevates `LOCAL` content to `PUBLIC` because a score exceeds a threshold is superseded by the invariants below.

## Non-negotiable authority boundary

- **Trust is evidence, not permission.** A high competence, reputation, integrity, or Sybil-resistance score may inform a user-facing explanation or a recommendation. It must never grant authority to encode, disclose, export, or broadcast user data.
- **Explicit consent controls the outbound action.** Moving data from `PRIVATE` or `LOCAL` to a `PUBLIC` sink requires a valid, revocable grant bound to the relevant data scope, recipient/destination, purpose, and time/expiry. A domain-level preference is not sufficient evidence of consent for every future action or data type.
- **Private remains non-overridable.** No profile, proof, classification, or model output may promote `PRIVATE` data.
- **Revoke at the authority boundary.** After revocation acknowledgement, queued work must re-check the grant before side effects; stale queued or in-flight work must not continue under revoked authority.
- **Fail closed and explain.** Missing scope, expired grants, malformed inputs, unavailable policy evaluation, and schema/version mismatch deny the outbound action and expose a clear, local explanation. They do not silently fall back to trust scores.
- **Minimize identity disclosure.** A zero-knowledge or aggregate proof may reduce the data revealed while evaluating a request, but proving competence does not prove consent or authorize export.

## Safe role for sovereign profile information

A future profile-aware interface may use a verified profile to suggest that the user review a sharing request, explain why a destination may be useful, or tailor non-sensitive UI. The actual policy decision must remain independent of the profile's trust/competence score and must require the scoped consent grant described above. The grant and decision should be inspectable, revocable, and auditable without keeping a centralized history of visited pages or raw page contents by default.

## Required evidence before implementation

Any profile-aware sharing feature must include adversarial tests showing:

1. Different trust/competence scores do not change the result when consent state and request scope are identical.
2. No `PRIVATE` or `LOCAL` data reaches `PUBLIC` without valid scoped consent.
3. Changing the data scope, recipient, purpose, expiry, or policy version invalidates the grant unless the grant explicitly covers that value.
4. Revocation acknowledgement prevents later queued operations from completing.
5. Unknown/malformed policy and telemetry failure do not produce an allow decision.
6. Raw event traces bind to exact code/policy revisions and are reviewed independently.

These are proposed test requirements, not claims that the current implementation already enforces scoped grants or revocation of in-flight operations.
