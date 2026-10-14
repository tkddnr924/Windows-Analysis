//! Bounded dependency-aware runner for independent overview builders.
use std::collections::HashSet;

use anyhow::{anyhow, Context, Result};
use parking_lot::{Condvar, Mutex};

pub(super) type TaskResult = Result<Vec<(String, usize)>>;

/// One builder producing a single documented table.
pub(super) fn table<'s>(
    name: &'static str,
    after: &'static [&'static str],
    build: impl FnOnce() -> Result<usize> + Send + 's,
) -> Task<'s> {
    Task { name, after, run: Box::new(move || Ok(vec![(name.to_string(), build()?)])) }
}

pub(super) struct Task<'s> {
    pub name: &'static str,
    pub after: &'static [&'static str],
    pub run: Box<dyn FnOnce() -> TaskResult + Send + 's>,
}

/// Upper bound on concurrent builders. Measured on the IDC case (release):
/// 2 workers 167s, 4 169s, 8 172s vs 220s sequential — more workers only add
/// disk contention to the RegistryExplorer critical path.
const MAX_WORKERS: usize = 2;

pub(super) fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS)
}

struct State<'s> {
    pending: Vec<Option<Task<'s>>>,
    done: HashSet<&'static str>,
    results: Vec<Option<TaskResult>>,
    running: usize,
    failed: bool,
    stalled: bool,
    /// First builder panic, re-raised on the caller after all workers exit.
    panic: Option<Box<dyn std::any::Any + Send>>,
}

/// Runs each task once its `after` tasks succeeded, on up to `workers`
/// threads. Results keep task order; the first failure (in task order) is
/// returned and no further tasks start after a failure.
pub(super) fn run_graph(tasks: Vec<Task<'_>>, workers: usize) -> Result<Vec<(String, usize)>> {
    let names: Vec<&'static str> = tasks.iter().map(|task| task.name).collect();
    let known: HashSet<&'static str> = names.iter().copied().collect();
    for task in &tasks {
        if let Some(missing) = task.after.iter().find(|dep| !known.contains(*dep)) {
            return Err(anyhow!("{}: unknown prerequisite {missing}", task.name));
        }
    }
    let count = tasks.len();
    let state = Mutex::new(State {
        pending: tasks.into_iter().map(Some).collect(),
        done: HashSet::new(),
        results: (0..count).map(|_| None).collect(),
        running: 0,
        failed: false,
        stalled: false,
        panic: None,
    });
    let wake = Condvar::new();
    std::thread::scope(|scope| {
        for _ in 0..workers.clamp(1, count.max(1)) {
            scope.spawn(|| worker(&state, &wake));
        }
    });
    let mut state = state.into_inner();
    if let Some(payload) = state.panic.take() {
        std::panic::resume_unwind(payload);
    }
    if state.stalled {
        return Err(anyhow!("overview builders have a dependency cycle"));
    }
    let mut out = Vec::new();
    for result in state.results.into_iter().flatten() {
        out.extend(result?);
    }
    Ok(out)
}

fn worker(state: &Mutex<State<'_>>, wake: &Condvar) {
    let mut guard = state.lock();
    loop {
        if guard.failed {
            return;
        }
        let ready = {
            let State { pending, done, .. } = &mut *guard;
            pending.iter().position(|slot| {
                slot.as_ref()
                    .is_some_and(|task| task.after.iter().all(|dep| done.contains(dep)))
            })
        };
        if let Some(index) = ready {
            let Some(task) = guard.pending[index].take() else {
                continue;
            };
            guard.running += 1;
            drop(guard);
            let name = task.name;
            let started = std::time::Instant::now();
            // A panic must still release waiting workers, or the scope never ends.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task.run));
            crate::pipeline::append_current_log_lifecycle(&format!(
                "overview_task_finished name={name} ms={}",
                started.elapsed().as_millis()
            ));
            guard = state.lock();
            guard.running -= 1;
            match outcome {
                Ok(result) => {
                    let result = result.with_context(|| format!("{name} 생성"));
                    match &result {
                        Ok(_) => {
                            guard.done.insert(name);
                        }
                        Err(_) => guard.failed = true,
                    }
                    guard.results[index] = Some(result);
                }
                Err(payload) => {
                    guard.failed = true;
                    if guard.panic.is_none() {
                        guard.panic = Some(payload);
                    }
                }
            }
            wake.notify_all();
            continue;
        }
        if guard.pending.iter().all(Option::is_none) {
            return;
        }
        if guard.running == 0 {
            // Nothing runnable and nothing in flight: a cycle.
            guard.failed = true;
            guard.stalled = true;
            wake.notify_all();
            return;
        }
        wake.wait(&mut guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    fn task<'s>(
        name: &'static str,
        after: &'static [&'static str],
        log: &'s Mutex<Vec<&'static str>>,
        fail: bool,
    ) -> Task<'s> {
        Task {
            name,
            after,
            run: Box::new(move || {
                std::thread::sleep(std::time::Duration::from_millis(5));
                log.lock().push(name);
                if fail {
                    anyhow::bail!("boom");
                }
                Ok(vec![(name.to_string(), 1)])
            }),
        }
    }

    #[test]
    fn dependents_run_after_prerequisites_and_results_keep_task_order() {
        let log = Mutex::new(Vec::new());
        let tasks = vec![
            task("c", &["a", "b"], &log, false),
            task("a", &[], &log, false),
            task("b", &["a"], &log, false),
            task("d", &[], &log, false),
        ];
        let out = run_graph(tasks, 4).unwrap();
        let names: Vec<_> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["c", "a", "b", "d"]);
        let log = log.into_inner();
        let at = |n| log.iter().position(|x| *x == n).unwrap();
        assert!(at("a") < at("b") && at("b") < at("c"));
    }

    #[test]
    fn failure_is_named_and_dependents_never_run() {
        let log = Mutex::new(Vec::new());
        let tasks = vec![task("a", &[], &log, true), task("b", &["a"], &log, false)];
        let error = run_graph(tasks, 2).unwrap_err();
        assert!(format!("{error:#}").contains("a") && format!("{error:#}").contains("boom"));
        assert!(!log.into_inner().contains(&"b"));
    }

    #[test]
    fn builder_panic_with_waiting_dependent_propagates_instead_of_hanging() {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(|| {
                let log = Mutex::new(Vec::new());
                let tasks = vec![
                    Task { name: "a", after: &[], run: Box::new(|| panic!("builder bug")) },
                    task("b", &["a"], &log, false),
                    task("c", &[], &log, false),
                ];
                let _ = run_graph(tasks, 2);
            });
            let _ = sent.send(outcome.is_err());
        });
        let panicked = received
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("run_graph hung after a builder panic");
        assert!(panicked, "the builder panic must reach the caller");
    }

    #[test]
    fn unknown_or_cyclic_dependencies_are_errors() {
        let log = Mutex::new(Vec::new());
        assert!(run_graph(vec![task("a", &["missing"], &log, false)], 2).is_err());
        let cyclic = vec![task("a", &["b"], &log, false), task("b", &["a"], &log, false)];
        assert!(run_graph(cyclic, 2).is_err());
        assert!(log.into_inner().is_empty());
    }
}
