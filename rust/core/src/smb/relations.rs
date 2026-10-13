//! Source-local correlation for classified SMB events.
//!
//! One instance is one *proven* logon lifetime: a successful network logon
//! opens it, the matching logoff closes it, and only records that fall inside
//! that open window are attributed to it. Everything else stays unlinked
//! context — it is retained, just not attributed.
//!
//! Hard boundaries:
//!
//! * The same collected log (`source_scope`) and computer; both must be known.
//!   A number in another log is another ID namespace.
//! * A restart (4608) or a cleared log (1102) closes every open instance: the
//!   same ID afterwards is a different instance.
//! * Only a successful logon opens an instance. A failed logon never does, and
//!   a share-audit record never invents one.
//! * A logoff before its logon and a record with no open instance are not
//!   linked — no time window and no account-name guessing.
//! * Measured exception, by explicit identity only: Windows writes the 4672
//!   of a network logon *before* its 4624 (lower EventRecordID, same or 1 ms
//!   earlier timestamp). Such a privilege record is attached to the **first**
//!   open of that logon ID when both sides carry the same confirmed SID. It
//!   is dropped at a restart/log-clear, dropped once that ID has been opened
//!   or closed before, and never carried into a later reuse. Everything
//!   outside this rule — unknown SID, different SID, privileges after a close
//!   — stays unlinked context.
//! * Two opens of one ID without a close in between are ambiguous: the whole
//!   instance is left unlinked.
//! * Two confirmed, different SIDs are two principals: no definite link.
//!
//! Records are never reordered or removed; the only mutation is
//! `logon_instance`.

use std::collections::HashMap;

use super::{SmbEvent, SmbRelation, SmbRole};
use crate::derived::normalize_logon_id;

/// A proven logon lifetime: the opening record plus everything observed while
/// it was open (the closing logoff included).
struct Instance {
    key: String,
    opener: usize,
    members: Vec<usize>,
    /// Privilege records written just before this ID's first open. The
    /// Security log writes 4672 ahead of its 4624 (lower EventRecordID, same
    /// or 1 ms earlier timestamp), so they are attached on the explicit logon
    /// ID plus an equal confirmed SID — never on a time window or a name.
    prelogon: Vec<usize>,
    /// A second open of the same ID without a close: nothing is attributed.
    ambiguous: bool,
}

/// A confirmed SID, if this record names one. The S-1-0-0 placeholder and an
/// empty value identify nobody and never block a link.
fn confirmed_sid(event: &SmbEvent<'_>) -> Option<String> {
    if event.account_sid_is_placeholder || event.account_sid.is_empty() {
        return None;
    }
    Some(event.account_sid.to_ascii_uppercase())
}

/// Assign bounded instances and return the definite context links, ordered by
/// (main, context).
pub(super) fn link(events: &mut [SmbEvent<'_>]) -> Vec<SmbRelation> {
    // Records without a timestamp cannot be placed between an open and a
    // close, and a record with no known log or computer cannot be bounded at
    // all, so neither joins an instance.
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (index, event) in events.iter().enumerate() {
        if event.timestamp.is_empty() || event.source_scope.is_empty() || event.computer.is_empty()
        {
            continue;
        }
        groups
            .entry((event.source_scope.clone(), event.computer.to_string()))
            .or_default()
            .push(index);
    }
    let mut scopes: Vec<(String, String)> = groups.keys().cloned().collect();
    scopes.sort();

    let mut instances: Vec<Instance> = Vec::new();
    for scope in scopes {
        let mut group = groups.remove(&scope).unwrap_or_default();
        group.sort_by(|a, b| events[*a].timestamp.cmp(events[*b].timestamp).then(a.cmp(b)));
        // Normalised logon ID -> currently open instance.
        let mut open: HashMap<String, usize> = HashMap::new();
        // Privilege records waiting for the first open of their ID.
        let mut pending: HashMap<String, Vec<usize>> = HashMap::new();
        // IDs already opened in this generation: their pending evidence is
        // spent and must never be carried into a later reuse.
        let mut opened: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut generation = 0usize;
        for index in group {
            if matches!(events[index].boundary_kind, "system_start" | "log_cleared") {
                open.clear();
                pending.clear();
                opened.clear();
                generation += 1;
                continue;
            }
            let logon_id = normalize_logon_id(&events[index].logon_id);
            if logon_id.is_empty() {
                continue;
            }
            match events[index].event_kind {
                // Only an authenticated logon opens a lifetime.
                "network_logon_success" => match open.get(&logon_id).copied() {
                    Some(existing) => {
                        // Reused while still open: which open owns the later
                        // context is unknowable, so attribute nothing.
                        instances[existing].ambiguous = true;
                        instances[existing].members.push(index);
                        pending.remove(&logon_id);
                    }
                    None => {
                        // Pending privilege evidence belongs to the *first*
                        // open of this ID only.
                        let prelogon = match opened.insert(logon_id.clone()) {
                            true => pending.remove(&logon_id).unwrap_or_default(),
                            false => {
                                pending.remove(&logon_id);
                                Vec::new()
                            }
                        };
                        instances.push(Instance {
                            key: format!(
                                "{}|{}|g{}|{}|i{}",
                                scope.0,
                                scope.1,
                                generation,
                                logon_id,
                                instances.len()
                            ),
                            opener: index,
                            members: vec![index],
                            prelogon,
                            ambiguous: false,
                        });
                        open.insert(logon_id, instances.len() - 1);
                    }
                },
                // The close belongs to the instance it ends; a logoff with no
                // open instance (including one recorded before its logon) is
                // unlinked context, and it voids any pending evidence.
                "logon_instance_end" => {
                    pending.remove(&logon_id);
                    if let Some(instance) = open.remove(&logon_id) {
                        instances[instance].members.push(index);
                    }
                }
                // Privileges inside an open instance are members; before the
                // first open they wait for it; after a close they are orphans.
                "special_privileges_assigned" => match open.get(&logon_id).copied() {
                    Some(instance) => instances[instance].members.push(index),
                    None => {
                        if !opened.contains(&logon_id) {
                            pending.entry(logon_id).or_default().push(index);
                        }
                    }
                },
                // Anything else is attributed only while the instance is open.
                _ => {
                    if let Some(&instance) = open.get(&logon_id) {
                        instances[instance].members.push(index);
                    }
                }
            }
        }
    }

    let mut relations: Vec<SmbRelation> = Vec::new();
    for instance in &instances {
        if instance.ambiguous {
            continue;
        }
        let opener_sid = confirmed_sid(&events[instance.opener]);
        for &index in &instance.members {
            events[index].logon_instance = instance.key.clone();
        }
        for &index in &instance.members {
            let kind = match events[index].event_kind {
                "logon_instance_end" => "logon_instance_end",
                "special_privileges_assigned" => "special_privileges",
                _ => continue,
            };
            if events[index].role != SmbRole::Context {
                continue;
            }
            // Two confirmed and different principals on one ID: keep the
            // context, drop the claim.
            if let (Some(opener), Some(member)) = (&opener_sid, confirmed_sid(&events[index])) {
                if opener != &member {
                    continue;
                }
            }
            relations.push(SmbRelation {
                main_index: instance.opener,
                context_index: index,
                kind,
                basis: "same_logon_id_bounded_instance",
                logon_instance: instance.key.clone(),
                logon_id: events[index].logon_id.clone(),
            });
        }
        // Privileges recorded just before this ID's first open. Here the SID
        // must be confirmed on both sides and equal — an unknown principal is
        // not enough outside the open window.
        for &index in &instance.prelogon {
            if events[index].role != SmbRole::Context {
                continue;
            }
            let matched = match (&opener_sid, confirmed_sid(&events[index])) {
                (Some(opener), Some(member)) => *opener == member,
                _ => false,
            };
            if !matched {
                continue;
            }
            events[index].logon_instance = instance.key.clone();
            relations.push(SmbRelation {
                main_index: instance.opener,
                context_index: index,
                kind: "special_privileges",
                basis: "same_logon_id_sid_prelogon_privileges",
                logon_instance: instance.key.clone(),
                logon_id: events[index].logon_id.clone(),
            });
        }
    }
    relations.sort_by_key(|relation| (relation.main_index, relation.context_index));
    relations
}
