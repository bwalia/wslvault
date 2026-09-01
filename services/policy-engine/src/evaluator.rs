//! Compiled policy evaluation for the WSLVault policy engine.
//!
//! The evaluator works in two phases:
//!   1. **Compilation** – `PolicyDocument`s from the store are pre-processed into
//!      a `CompiledPolicies` map for O(1) policy name lookup.
//!   2. **Evaluation** – `evaluate` iterates over the requested policy names,
//!      matches path patterns, and applies the deny-wins rule.

use std::collections::HashMap;

use tracing::{debug, trace};

use crate::model::{Capability, PolicyDecision, PolicyRule};

/// Pre-processed view of all policies loaded into the engine.
///
/// Keyed by **(tenant_id, policy_name)** so individual lookups stay O(1) while
/// remaining scoped to the tenant that owns the policy.
///
/// The tenant half of that key is load-bearing. This map was previously keyed
/// on the policy name alone, with the tenant discarded at compile time. Two
/// tenants that each defined a policy called `admin` — the single most likely
/// name in any deployment — collapsed into one entry, and whichever compiled
/// last silently supplied its rules to both. A principal in tenant B carrying
/// the name `admin` was then evaluated against tenant A's `admin` rules.
#[derive(Debug, Default, Clone)]
pub struct CompiledPolicies {
    /// Map from (tenant_id, policy name) to its compiled rule list.
    pub policies: HashMap<(String, String), Vec<PolicyRule>>,
}

impl CompiledPolicies {
    /// Create a new, empty compiled policy set.
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Insert or replace a single policy within a tenant.
    pub fn upsert(&mut self, tenant_id: String, name: String, rules: Vec<PolicyRule>) {
        self.policies.insert((tenant_id, name), rules);
    }

    /// Remove a policy from a tenant. Returns true if the policy existed.
    pub fn remove(&mut self, tenant_id: &str, name: &str) -> bool {
        self.policies
            .remove(&(tenant_id.to_string(), name.to_string()))
            .is_some()
    }
}

/// Evaluate whether the given `action` on `resource` is permitted by any of
/// the named `policies` inside the compiled set.
///
/// Deny semantics:
/// - A `Capability::Deny` in any matching rule immediately returns `Deny`.
/// - At least one matching rule must contain the required capability for
///   `Allow` to be returned.
/// - If no policy names are provided, or none match, the result is `Deny`.
///
/// # Arguments
///
/// * `compiled`  – The pre-compiled policies snapshot.
/// * `tenant_id` – The tenant the caller belongs to. Policy names are resolved
///   only within this tenant, so naming a policy that exists in a different
///   tenant matches nothing.
/// * `policies`  – Names of the policies to evaluate (e.g. the principal's assigned policies).
/// * `action`    – Action string such as `"secret:read"` or just `"read"`.
/// * `resource`  – The resource path being accessed, e.g. `"secret/db/prod/password"`.
pub fn evaluate(
    compiled: &CompiledPolicies,
    tenant_id: &str,
    policies: &[String],
    action: &str,
    resource: &str,
) -> PolicyDecision {
    // Resolve the requested action to a capability.
    let required_capability = match Capability::from_action(action) {
        Some(cap) => cap,
        None => {
            debug!(action, "unknown action – denying by default");
            return PolicyDecision::Deny {
                reason: format!("unknown action: {action}"),
            };
        }
    };

    let mut any_allow = false;

    for policy_name in policies {
        // Scoped lookup: a policy name only resolves inside the caller's own
        // tenant, never against an identically named policy in another.
        let key = (tenant_id.to_string(), policy_name.clone());
        let rules = match compiled.policies.get(&key) {
            Some(r) => r,
            None => {
                trace!(
                    tenant_id,
                    policy_name,
                    "policy not found in this tenant's compiled set – skipping"
                );
                continue;
            }
        };

        for rule in rules {
            // Check whether any of this rule's path patterns match the resource.
            let path_matched = rule.paths.iter().any(|pattern| {
                let matched = glob_match(pattern, resource);
                trace!(pattern, resource, matched, "path match check");
                matched
            });

            if !path_matched {
                continue;
            }

            // Deny capability is an explicit deny and always wins.
            if rule.capabilities.contains(&Capability::Deny) {
                debug!(
                    policy = policy_name.as_str(),
                    resource, action, "explicit deny rule matched"
                );
                return PolicyDecision::Deny {
                    reason: format!(
                        "explicit deny in policy '{policy_name}' for resource '{resource}'"
                    ),
                };
            }

            if rule.capabilities.contains(&required_capability) {
                debug!(
                    policy = policy_name.as_str(),
                    resource, action, "allow rule matched"
                );
                any_allow = true;
                // Continue scanning remaining rules – a later deny still wins.
            }
        }
    }

    if any_allow {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny {
            reason: format!("no policy grants '{action}' on resource '{resource}'"),
        }
    }
}

/// Match a glob pattern against a resource path.
///
/// Supported wildcards:
/// - `*`  – Matches any characters within a single path segment (no `/`).
/// - `**` – Matches zero or more path segments including `/`.
///
/// Both the pattern and path are treated as `/`-delimited strings. Matching
/// is case-sensitive.
///
/// # Examples
///
/// ```
/// assert!(glob_match("secret/*", "secret/db"));
/// assert!(!glob_match("secret/*", "secret/db/prod"));
/// assert!(glob_match("secret/**", "secret/db/prod/password"));
/// assert!(glob_match("secret/**", "secret/"));
/// ```
fn glob_match(pattern: &str, path: &str) -> bool {
    // Delegate to a recursive helper that operates on byte slices of the
    // remaining pattern and path segments.
    glob_match_recursive(pattern, path)
}

fn glob_match_recursive(pattern: &str, path: &str) -> bool {
    // Base cases.
    if pattern.is_empty() {
        return path.is_empty();
    }

    // Check for leading `**` wildcard.
    if pattern.starts_with("**/") || pattern == "**" {
        // `**` followed by `/rest` must match zero or more full segments.
        let rest_pattern = if pattern == "**" { "" } else { &pattern[3..] };

        // Try matching rest_pattern against every suffix of path (including
        // the full path itself, representing zero segments consumed by `**`).
        if glob_match_recursive(rest_pattern, path) {
            return true;
        }
        // Consume one segment at a time and retry.
        let mut remaining = path;
        loop {
            if let Some(slash_pos) = remaining.find('/') {
                remaining = &remaining[slash_pos + 1..];
                if glob_match_recursive(rest_pattern, remaining) {
                    return true;
                }
            } else {
                // No more slashes – consume the whole remaining string and
                // try once more (handles trailing segment with no `/`).
                if glob_match_recursive(rest_pattern, "") {
                    return true;
                }
                break;
            }
        }
        return false;
    }

    // Split the pattern at the first `/` to process one segment at a time.
    let (pattern_segment, pattern_rest) = match pattern.find('/') {
        Some(pos) => (&pattern[..pos], &pattern[pos + 1..]),
        None => (pattern, ""),
    };

    // Split the path at the first `/` to align with the pattern segment.
    let (path_segment, path_rest) = match path.find('/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, ""),
    };

    // Match the current segment.
    if !segment_match(pattern_segment, path_segment) {
        return false;
    }

    // If there is more pattern but path is exhausted (or vice versa), check
    // whether the remainder can still match an empty string.
    if pattern_rest.is_empty() {
        return path_rest.is_empty();
    }

    glob_match_recursive(pattern_rest, path_rest)
}

/// Match a single path segment against a single-segment pattern.
/// Within a segment, `*` matches any sequence of characters that does not
/// include `/` (which cannot appear in a segment by definition here).
fn segment_match(pattern: &str, segment: &str) -> bool {
    if pattern == "*" {
        // `*` matches any non-empty or empty single segment.
        return true;
    }

    // Handle patterns that contain `*` as an infix wildcard within a segment,
    // e.g. `prefix-*-suffix`.
    let mut pat_chars = pattern.chars().peekable();
    let mut seg_chars = segment.chars().peekable();

    while let Some(p) = pat_chars.next() {
        match p {
            '*' => {
                // Consume the minimal number of characters in the segment
                // required to satisfy the remainder of the pattern.
                let rest_pattern: String = pat_chars.collect();
                // Try every suffix of the remaining segment characters.
                // We collect into a Vec of chars first so that we can slice
                // at char boundaries rather than byte boundaries, preventing
                // a panic on multi-byte Unicode characters in path segments.
                let remaining_chars: Vec<char> = seg_chars.collect();
                for start in 0..=remaining_chars.len() {
                    let suffix: String = remaining_chars[start..].iter().collect();
                    if segment_match(&rest_pattern, &suffix) {
                        return true;
                    }
                }
                return false;
            }
            literal => match seg_chars.next() {
                Some(s) if s == literal => {}
                _ => return false,
            },
        }
    }

    // Pattern exhausted – segment must also be exhausted.
    seg_chars.next().is_none()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::model::{Capability, PolicyRule};

    /// Tenant every helper-built policy belongs to, unless stated otherwise.
    const T: &str = "tenant-a";

    fn make_compiled(policies: Vec<(&str, Vec<PolicyRule>)>) -> CompiledPolicies {
        let mut c = CompiledPolicies::new();
        for (name, rules) in policies {
            c.upsert(T.to_string(), name.to_string(), rules);
        }
        c
    }

    fn rule(paths: &[&str], caps: &[Capability]) -> PolicyRule {
        PolicyRule {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            capabilities: caps.iter().copied().collect::<HashSet<_>>(),
        }
    }

    // --- glob_match tests ---

    #[test]
    fn exact_path_matches() {
        assert!(glob_match("secret/db/password", "secret/db/password"));
        assert!(!glob_match("secret/db/password", "secret/db/other"));
    }

    #[test]
    fn single_star_matches_one_segment() {
        assert!(glob_match("secret/*", "secret/db"));
        assert!(!glob_match("secret/*", "secret/db/prod"));
        assert!(!glob_match("secret/*", "other/db"));
    }

    #[test]
    fn double_star_matches_multiple_segments() {
        assert!(glob_match("secret/**", "secret/db/prod/password"));
        assert!(glob_match("secret/**", "secret/a"));
        assert!(glob_match("secret/**", "secret/"));
        assert!(!glob_match("secret/**", "other/db"));
    }

    #[test]
    fn double_star_at_root() {
        assert!(glob_match("**", "secret/db/prod"));
        assert!(glob_match("**", "anything"));
    }

    #[test]
    fn infix_wildcard_in_segment() {
        assert!(glob_match("secret/prod-*", "secret/prod-db"));
        assert!(!glob_match("secret/prod-*", "secret/staging-db"));
    }

    // --- evaluate tests ---

    #[test]
    fn allow_when_capability_matches() {
        let compiled = make_compiled(vec![(
            "read-policy",
            vec![rule(&["secret/*"], &[Capability::Read])],
        )]);
        let decision = evaluate(
            &compiled,
            T,
            &["read-policy".to_string()],
            "secret:read",
            "secret/db",
        );
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn deny_when_no_matching_capability() {
        let compiled = make_compiled(vec![(
            "read-policy",
            vec![rule(&["secret/*"], &[Capability::Read])],
        )]);
        let decision = evaluate(
            &compiled,
            T,
            &["read-policy".to_string()],
            "secret:write",
            "secret/db",
        );
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn explicit_deny_wins_over_allow() {
        let compiled = make_compiled(vec![
            (
                "allow-policy",
                vec![rule(&["secret/**"], &[Capability::Read])],
            ),
            (
                "deny-policy",
                vec![rule(&["secret/db/**"], &[Capability::Deny])],
            ),
        ]);
        // The deny-policy matches secret/db/prod, so even though allow-policy
        // also matches, the result should be Deny.
        let decision = evaluate(
            &compiled,
            T,
            &["allow-policy".to_string(), "deny-policy".to_string()],
            "secret:read",
            "secret/db/prod",
        );
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn unknown_action_is_denied() {
        let compiled = CompiledPolicies::new();
        let decision = evaluate(&compiled, T, &[], "secret:teleport", "secret/db");
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn empty_policy_list_is_denied() {
        let compiled = CompiledPolicies::new();
        let decision = evaluate(&compiled, T, &[], "secret:read", "secret/db");
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn missing_policy_name_is_skipped() {
        let compiled = CompiledPolicies::new();
        let decision = evaluate(
            &compiled,
            T,
            &["nonexistent".to_string()],
            "secret:read",
            "secret/db",
        );
        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    /// The regression this key change exists for: two tenants each defining a
    /// policy of the same name must not see each other's rules. Before the
    /// snapshot was tenant-scoped, the second `upsert` overwrote the first and
    /// tenant B's principals were evaluated against tenant A's `admin` rules.
    #[test]
    fn identically_named_policies_do_not_leak_across_tenants() {
        let mut compiled = CompiledPolicies::new();
        compiled.upsert(
            "tenant-a".to_string(),
            "admin".to_string(),
            vec![rule(&["secret/**"], &[Capability::Read, Capability::Write])],
        );
        compiled.upsert(
            "tenant-b".to_string(),
            "admin".to_string(),
            vec![rule(&["secret/public/**"], &[Capability::Read])],
        );

        let names = vec!["admin".to_string()];

        // Tenant A keeps its own broad grant.
        assert!(matches!(
            evaluate(&compiled, "tenant-a", &names, "read", "secret/db/prod"),
            PolicyDecision::Allow
        ));

        // Tenant B's `admin` must NOT inherit tenant A's paths.
        assert!(matches!(
            evaluate(&compiled, "tenant-b", &names, "read", "secret/db/prod"),
            PolicyDecision::Deny { .. }
        ));

        // ...but tenant B's own rule still works.
        assert!(matches!(
            evaluate(&compiled, "tenant-b", &names, "read", "secret/public/motd"),
            PolicyDecision::Allow
        ));
    }

    /// A tenant that owns no policy of that name matches nothing, rather than
    /// falling through to some other tenant's definition.
    #[test]
    fn unknown_tenant_matches_no_policy() {
        let compiled = make_compiled(vec![(
            "reader",
            vec![rule(&["secret/**"], &[Capability::Read])],
        )]);
        assert!(matches!(
            evaluate(
                &compiled,
                "some-other-tenant",
                &["reader".to_string()],
                "read",
                "secret/db"
            ),
            PolicyDecision::Deny { .. }
        ));
    }
}
