//! Per-feature protection state evidence. Observations, runs and the latest
//! state stay separate so an observation gap is never read as a continuous
//! disabled period and a same-time conflict never becomes a decided state
//! (뷰어13 R02·R13·A04).
use super::{Cell, Ctx, DerivedDb};
use anyhow::Result;

pub(super) const FEATURE_REALTIME: &str = "realtime_protection";
pub(super) const FEATURE_ON_ACCESS: &str = "on_access";
pub(super) const FEATURE_IOAV: &str = "ioav";
pub(super) const FEATURE_BEHAVIOR: &str = "behavior_monitoring";
pub(super) const FEATURE_MALWARE_SCANNING: &str = "malware_scanning";
pub(super) const FEATURE_VIRUS_SCANNING: &str = "virus_scanning";

pub(super) const BASIS_HEALTH: &str = "health_report";
pub(super) const BASIS_STATE_EVENT: &str = "state_event";
pub(super) const BASIS_CONFIG_CHANGE: &str = "config_change";

pub(super) const STATE_ON: &str = "on";
pub(super) const STATE_OFF: &str = "off";
pub(super) const STATE_UNKNOWN: &str = "unknown";

/// One observed feature state taken from a single stored Defender row.
pub(super) struct Observation {
    pub record_id: String,
    pub feature: &'static str,
    pub state: &'static str,
    pub state_raw: Option<String>,
    pub basis: &'static str,
    pub timestamp: Option<String>,
    pub timestamp_kind: Option<&'static str>,
    pub event_id: Option<i64>,
    pub event_record_id: Option<i64>,
    /// Source row order; the tie-break after the recorded event record id.
    pub order: usize,
}

fn parse(time: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S"))
        .ok()
}

/// Seconds between two stored timestamps; unparsable values stay unknown.
fn gap(from: &str, to: &str) -> Cell {
    match (parse(from), parse(to)) {
        (Some(from), Some(to)) => Cell::Int(to.signed_duration_since(from).num_seconds()),
        _ => Cell::Null,
    }
}

fn text(value: &str) -> Cell {
    Cell::Text(value.to_string())
}

fn opt(value: Option<&str>) -> Cell {
    value.map(text).unwrap_or(Cell::Null)
}

pub(super) fn populate(ctx: &Ctx, db: &mut DerivedDb, observations: &[Observation]) -> Result<()> {
    let mut features: Vec<&'static str> = Vec::new();
    for observation in observations {
        if !features.contains(&observation.feature) {
            features.push(observation.feature);
        }
    }
    features.sort_unstable();

    for feature in features {
        let mut timed: Vec<&Observation> = observations
            .iter()
            .filter(|o| o.feature == feature && o.timestamp.is_some())
            .collect();
        let untimed: Vec<&Observation> = observations
            .iter()
            .filter(|o| o.feature == feature && o.timestamp.is_none())
            .collect();
        // Confirmed log order: recorded time, then the event record id.
        timed.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.event_record_id.cmp(&b.event_record_id))
                .then(a.order.cmp(&b.order))
        });

        let same_time = |time: &str| -> i64 {
            timed
                .iter()
                .filter(|o| o.timestamp.as_deref() == Some(time))
                .count() as i64
        };
        let conflicting = |time: &str, state: &str| -> bool {
            timed.iter().any(|o| {
                o.timestamp.as_deref() == Some(time)
                    && o.state != state
                    && (o.state == STATE_ON || o.state == STATE_OFF)
                    && (state == STATE_ON || state == STATE_OFF)
            })
        };

        let mut previous_decided: Option<&str> = None;
        let mut previous_time: Option<&str> = None;
        for (ordinal, observation) in timed.iter().enumerate() {
            let time = observation.timestamp.as_deref().unwrap_or_default();
            let ambiguous = conflicting(time, observation.state);
            let decided = observation.state == STATE_ON || observation.state == STATE_OFF;
            let change_kind = if !decided {
                "undetermined"
            } else if previous_decided.is_none() {
                "initial_observation"
            } else if previous_decided == Some(observation.state) {
                "unchanged"
            } else {
                "transition"
            };
            let certainty = if !decided {
                "unknown"
            } else if ambiguous {
                "ambiguous"
            } else {
                "confirmed"
            };
            db.insert_child(
                "DefenderProtectionStates",
                &[
                    text(&uuid::Uuid::new_v4().to_string()),
                    text(ctx.host_id),
                    text(ctx.dataset_id),
                    text(feature),
                    text(observation.state),
                    opt(observation.state_raw.as_deref()),
                    text(observation.basis),
                    text(time),
                    opt(observation.timestamp_kind),
                    text(&observation.record_id),
                    observation.event_id.map(Cell::Int).unwrap_or(Cell::Null),
                    observation
                        .event_record_id
                        .map(Cell::Int)
                        .unwrap_or(Cell::Null),
                    Cell::Int(ordinal as i64),
                    opt(previous_decided),
                    text(change_kind),
                    Cell::Int(i64::from(ambiguous)),
                    Cell::Int(same_time(time)),
                    previous_time.map(|from| gap(from, time)).unwrap_or(Cell::Null),
                    text(certainty),
                ],
            )?;
            previous_time = observation.timestamp.as_deref();
            if decided {
                previous_decided = Some(observation.state);
            }
        }
        for (ordinal, observation) in untimed.iter().enumerate() {
            db.insert_child(
                "DefenderProtectionStates",
                &[
                    text(&uuid::Uuid::new_v4().to_string()),
                    text(ctx.host_id),
                    text(ctx.dataset_id),
                    text(feature),
                    text(observation.state),
                    opt(observation.state_raw.as_deref()),
                    text(observation.basis),
                    Cell::Null,
                    Cell::Null,
                    text(&observation.record_id),
                    observation.event_id.map(Cell::Int).unwrap_or(Cell::Null),
                    observation
                        .event_record_id
                        .map(Cell::Int)
                        .unwrap_or(Cell::Null),
                    Cell::Int((timed.len() + ordinal) as i64),
                    Cell::Null,
                    text("unrecorded_time"),
                    Cell::Int(0),
                    Cell::Int(0),
                    Cell::Null,
                    text("unknown"),
                ],
            )?;
        }

        // Runs of equal decided states; unknown observations never join a run.
        let decided: Vec<&Observation> = timed
            .iter()
            .copied()
            .filter(|o| o.state == STATE_ON || o.state == STATE_OFF)
            .collect();
        let mut runs: Vec<(usize, usize)> = Vec::new();
        for index in 0..decided.len() {
            match runs.last_mut() {
                Some(last) if decided[last.1].state == decided[index].state => last.1 = index,
                _ => runs.push((index, index)),
            }
        }
        for (position, (start, end)) in runs.iter().enumerate() {
            let first = decided[*start];
            let last = decided[*end];
            let next = runs.get(position + 1).map(|(next, _)| decided[*next]);
            let start_time = first.timestamp.as_deref().unwrap_or_default();
            let end_time = last.timestamp.as_deref().unwrap_or_default();
            let prior_gap = runs
                .get(position.wrapping_sub(1))
                .filter(|_| position > 0)
                .map(|(_, previous_end)| {
                    gap(
                        decided[*previous_end].timestamp.as_deref().unwrap_or_default(),
                        start_time,
                    )
                })
                .unwrap_or(Cell::Null);
            let ambiguous = conflicting(start_time, first.state) || conflicting(end_time, last.state);
            db.insert_child(
                "DefenderProtectionIntervals",
                &[
                    text(&uuid::Uuid::new_v4().to_string()),
                    text(ctx.host_id),
                    text(ctx.dataset_id),
                    text(feature),
                    text(first.state),
                    text(if position == 0 {
                        "initial_observation"
                    } else {
                        "transition"
                    }),
                    text(start_time),
                    text(&first.record_id),
                    text(end_time),
                    text(&last.record_id),
                    Cell::Int((end - start + 1) as i64),
                    next.map(|next| text(next.state)).unwrap_or(Cell::Null),
                    next.map(|next| opt(next.timestamp.as_deref()))
                        .unwrap_or(Cell::Null),
                    next.map(|next| text(&next.record_id)).unwrap_or(Cell::Null),
                    next.map(|next| {
                        gap(end_time, next.timestamp.as_deref().unwrap_or_default())
                    })
                    .unwrap_or(Cell::Null),
                    text(if next.is_some() {
                        "state_change"
                    } else {
                        "open_end"
                    }),
                    prior_gap,
                    Cell::Int(i64::from(ambiguous)),
                    // The run proves its endpoints only, never the span between.
                    text("observed_endpoints_only"),
                ],
            )?;
        }

        // Latest state: only confirmed state events decide it.
        let last_time = decided.last().and_then(|o| o.timestamp.clone());
        let (state, certainty, tie_count, record_id, basis) = match last_time.as_deref() {
            Some(time) => {
                let at_time: Vec<&Observation> = decided
                    .iter()
                    .copied()
                    .filter(|o| o.timestamp.as_deref() == Some(time))
                    .collect();
                let conflict = at_time.iter().any(|o| o.state != at_time[0].state);
                let last = decided[decided.len() - 1];
                if conflict {
                    (
                        Cell::Null,
                        "ambiguous_tie",
                        at_time.len() as i64,
                        Cell::Null,
                        Cell::Null,
                    )
                } else {
                    (
                        text(last.state),
                        "confirmed",
                        at_time.len() as i64,
                        text(&last.record_id),
                        text(last.basis),
                    )
                }
            }
            None => (Cell::Null, "undetermined", 0, Cell::Null, Cell::Null),
        };
        let first_observed = decided.first().and_then(|o| o.timestamp.clone());
        db.insert_child(
            "DefenderProtectionLatest",
            &[
                text(&uuid::Uuid::new_v4().to_string()),
                text(ctx.host_id),
                text(ctx.dataset_id),
                text(feature),
                state,
                text(certainty),
                Cell::Int(tie_count),
                record_id,
                basis,
                Cell::Int(decided.len() as i64),
                Cell::Int(untimed.len() as i64),
                opt(first_observed.as_deref()),
                opt(last_time.as_deref()),
                // Period-scoped answers come from the stored observations.
                text("observed_range"),
            ],
        )?;
    }
    Ok(())
}
