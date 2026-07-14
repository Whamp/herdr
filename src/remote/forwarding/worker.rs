use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::protocol::{CorrelationId, ForwardSpec};

pub(super) const CONTROL_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlInvocation {
    pub(super) program: String,
    pub(super) args: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ControlAuthority {
    target: String,
    control_path: PathBuf,
    #[cfg(test)]
    test_invocation: Option<ControlInvocation>,
}

impl ControlAuthority {
    pub(crate) fn new(target: String, control_path: PathBuf) -> Self {
        Self {
            target,
            control_path,
            #[cfg(test)]
            test_invocation: None,
        }
    }

    #[cfg(test)]
    fn with_test_invocation(invocation: ControlInvocation) -> Self {
        Self {
            target: String::new(),
            control_path: PathBuf::new(),
            test_invocation: Some(invocation),
        }
    }

    fn invocation(&self, operation_name: &'static str, spec: ForwardSpec) -> ControlInvocation {
        #[cfg(test)]
        if let Some(invocation) = &self.test_invocation {
            return invocation.clone();
        }

        ControlInvocation {
            program: "ssh".to_string(),
            args: vec![
                "-F".to_string(),
                "/dev/null".to_string(),
                "-S".to_string(),
                self.control_path.to_string_lossy().into_owned(),
                "-O".to_string(),
                operation_name.to_string(),
                "-L".to_string(),
                spec.ssh_value(),
                self.target.clone(),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LocalhostPairSpec {
    ipv4: ForwardSpec,
    ipv6: ForwardSpec,
}

impl LocalhostPairSpec {
    pub(super) fn new(local_port: u16, remote_port: u16) -> Option<Self> {
        if local_port == 0 || remote_port == 0 {
            return None;
        }
        Some(Self {
            ipv4: ForwardSpec {
                local_address: super::protocol::LoopbackAddress::Ipv4([127, 0, 0, 1]),
                local_port,
                remote_address: super::protocol::LoopbackAddress::Ipv4([127, 0, 0, 1]),
                remote_port,
            },
            ipv6: ForwardSpec {
                local_address: super::protocol::LoopbackAddress::Ipv6,
                local_port,
                remote_address: super::protocol::LoopbackAddress::Ipv6,
                remote_port,
            },
        })
    }

    pub(super) const fn local_port(self) -> u16 {
        self.ipv4.local_port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlOperation {
    Forward(ForwardSpec),
    Cancel(ForwardSpec),
    ForwardPair(LocalhostPairSpec),
    CancelPair(LocalhostPairSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlResult {
    Succeeded,
    BindFailed,
    Rejected,
    TimedOut,
    PairSucceeded,
    PairFirstBindFailed,
    PairFirstFailed,
    PairFirstTimedOut,
    PairSecondFailed,
    PairCancellationSucceeded,
    PairCancellationFailed,
    MasterDied,
}

pub(super) trait CommandRunner: Send + Sync + 'static {
    /// Admits the command and starts its side effects only if `cancel` has not won the
    /// implementation's shared lifecycle boundary.
    fn run(&self, invocation: &ControlInvocation, timeout: Duration) -> ControlResult;

    /// Permanently closes command admission and settles any admitted command before returning.
    fn cancel(&self);
}

#[cfg(test)]
#[derive(Default)]
struct ProcessRunnerHooks {
    before_admission: Option<Arc<dyn Fn() + Send + Sync>>,
    after_spawn_before_publication: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    after_cancel_observed_lifecycle_contention: Option<Arc<dyn Fn() + Send + Sync>>,
    after_stopping: Option<Arc<dyn Fn() + Send + Sync>>,
    after_reap: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

#[derive(Default)]
struct ProcessLifecycle {
    stopping: bool,
    active: Option<Child>,
}

#[derive(Default)]
pub(super) struct ProcessCommandRunner {
    lifecycle: Mutex<ProcessLifecycle>,
    #[cfg(test)]
    hooks: ProcessRunnerHooks,
}

impl ProcessCommandRunner {
    fn terminate_and_reap(&self, mut child: Child) {
        #[cfg(test)]
        let child_id = child.id();
        let _ = child.kill();
        let wait_result = child.wait();
        #[cfg(test)]
        if wait_result.is_ok() {
            if let Some(hook) = &self.hooks.after_reap {
                hook(child_id);
            }
        }
        #[cfg(not(test))]
        let _ = wait_result;
    }

    #[cfg(test)]
    fn with_test_hooks(hooks: ProcessRunnerHooks) -> Self {
        Self {
            lifecycle: Mutex::new(ProcessLifecycle::default()),
            hooks,
        }
    }

    #[cfg(test)]
    fn has_active_child(&self) -> bool {
        self.lifecycle
            .lock()
            .is_ok_and(|lifecycle| lifecycle.active.is_some())
    }
}

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, invocation: &ControlInvocation, timeout: Duration) -> ControlResult {
        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_admission {
            hook();
        }

        let Ok(mut lifecycle) = self.lifecycle.lock() else {
            return ControlResult::Rejected;
        };
        if lifecycle.stopping || lifecycle.active.is_some() {
            return ControlResult::Rejected;
        }
        let child = match Command::new(&invocation.program)
            .args(&invocation.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return ControlResult::Rejected,
        };
        #[cfg(test)]
        if let Some(hook) = &self.hooks.after_spawn_before_publication {
            hook(child.id());
        }
        lifecycle.active = Some(child);
        drop(lifecycle);

        let deadline = Instant::now() + timeout;
        loop {
            let Ok(mut lifecycle) = self.lifecycle.lock() else {
                return ControlResult::Rejected;
            };
            let Some(child) = lifecycle.active.as_mut() else {
                return ControlResult::Rejected;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    let Some(mut child) = lifecycle.active.take() else {
                        return ControlResult::Rejected;
                    };
                    if status.success() {
                        return ControlResult::Succeeded;
                    }
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    return match classify_openssh_control_stderr(&stderr) {
                        OpenSshControlFailure::BindCollision => ControlResult::BindFailed,
                        OpenSshControlFailure::Rejected => ControlResult::Rejected,
                        OpenSshControlFailure::MasterDied => ControlResult::MasterDied,
                    };
                }
                Ok(None) if Instant::now() < deadline => {
                    drop(lifecycle);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    let Some(child) = lifecycle.active.take() else {
                        return ControlResult::Rejected;
                    };
                    drop(lifecycle);
                    self.terminate_and_reap(child);
                    return ControlResult::TimedOut;
                }
                Err(_) => {
                    let Some(child) = lifecycle.active.take() else {
                        return ControlResult::Rejected;
                    };
                    drop(lifecycle);
                    self.terminate_and_reap(child);
                    return ControlResult::Rejected;
                }
            }
        }
    }

    fn cancel(&self) {
        #[cfg(test)]
        if let Some(hook) = &self.hooks.after_cancel_observed_lifecycle_contention {
            if matches!(
                self.lifecycle.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                hook();
            }
        }

        let child = {
            let Ok(mut lifecycle) = self.lifecycle.lock() else {
                return;
            };
            #[cfg(test)]
            let newly_stopping = !lifecycle.stopping;
            lifecycle.stopping = true;
            #[cfg(test)]
            if newly_stopping {
                if let Some(hook) = &self.hooks.after_stopping {
                    hook();
                }
            }
            lifecycle.active.take()
        };
        if let Some(child) = child {
            self.terminate_and_reap(child);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenSshControlFailure {
    BindCollision,
    Rejected,
    MasterDied,
}

fn classify_openssh_control_stderr(stderr: &str) -> OpenSshControlFailure {
    let master_died = stderr.lines().any(|line| {
        let lowercase = line.trim().to_ascii_lowercase();
        (lowercase.starts_with("control socket connect(")
            && (lowercase.ends_with(": no such file or directory")
                || lowercase.ends_with(": connection refused")))
            || lowercase.contains("master is not running")
    });
    if master_died {
        return OpenSshControlFailure::MasterDied;
    }
    let collision = stderr.lines().any(|line| {
        let lowercase = line.trim().to_ascii_lowercase();
        let Some(binding) = lowercase.strip_prefix("bind [") else {
            return false;
        };
        let Some((address, after_address)) = binding.split_once("]:") else {
            return false;
        };
        let Some((port, reason)) = after_address.split_once(": ") else {
            return false;
        };
        !address.is_empty()
            && !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && reason == "address already in use"
    });
    if collision {
        OpenSshControlFailure::BindCollision
    } else {
        OpenSshControlFailure::Rejected
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WorkerJob {
    pub(super) id: CorrelationId,
    pub(super) operation: ControlOperation,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WorkerResult {
    pub(super) id: CorrelationId,
    pub(super) operation: ControlOperation,
    pub(super) result: ControlResult,
}

enum WorkerMessage {
    Run(WorkerJob),
    Shutdown,
}

pub(super) struct ControlWorker {
    sender: mpsc::Sender<WorkerMessage>,
    results: mpsc::Receiver<WorkerResult>,
    runner: Arc<dyn CommandRunner>,
    shutdown_fence: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ControlWorker {
    pub(super) fn start(
        authority: ControlAuthority,
        runner: Arc<dyn CommandRunner>,
        timeout: Duration,
    ) -> Self {
        Self::start_with_hook(authority, runner, timeout, || {})
    }

    fn start_with_hook(
        authority: ControlAuthority,
        runner: Arc<dyn CommandRunner>,
        timeout: Duration,
        before_receive: impl FnOnce() + Send + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let (result_sender, results) = mpsc::channel();
        let thread_runner = Arc::clone(&runner);
        let shutdown_fence = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_shutdown_fence = Arc::clone(&shutdown_fence);
        let thread = std::thread::spawn(move || {
            before_receive();
            while let Ok(message) = receiver.recv() {
                match message {
                    WorkerMessage::Run(job) => {
                        let result =
                            if thread_shutdown_fence.load(std::sync::atomic::Ordering::Acquire) {
                                ControlResult::Rejected
                            } else {
                                run_operation(
                                    &authority,
                                    thread_runner.as_ref(),
                                    job.operation,
                                    timeout,
                                )
                            };
                        if result_sender
                            .send(WorkerResult {
                                id: job.id,
                                operation: job.operation,
                                result,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    WorkerMessage::Shutdown => break,
                }
            }
        });
        Self {
            sender,
            results,
            runner,
            shutdown_fence,
            thread: Some(thread),
        }
    }

    pub(super) fn submit(&self, job: WorkerJob) -> io::Result<()> {
        self.sender
            .send(WorkerMessage::Run(job))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "forwarding worker closed"))
    }

    #[cfg(test)]
    pub(super) fn recv(&self) -> io::Result<WorkerResult> {
        self.results
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "forwarding worker closed"))
    }

    pub(super) fn try_recv(&self) -> Result<WorkerResult, mpsc::TryRecvError> {
        self.results.try_recv()
    }

    fn shutdown(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.shutdown_fence
            .store(true, std::sync::atomic::Ordering::Release);
        self.runner.cancel();
        let _ = self.sender.send(WorkerMessage::Shutdown);
        let _ = thread.join();
    }
}

fn run_operation(
    authority: &ControlAuthority,
    runner: &dyn CommandRunner,
    operation: ControlOperation,
    timeout: Duration,
) -> ControlResult {
    match operation {
        ControlOperation::Forward(spec) => {
            runner.run(&authority.invocation("forward", spec), timeout)
        }
        ControlOperation::Cancel(spec) => {
            runner.run(&authority.invocation("cancel", spec), timeout)
        }
        ControlOperation::ForwardPair(pair) => {
            let first = runner.run(&authority.invocation("forward", pair.ipv4), timeout);
            match first {
                ControlResult::Succeeded => {}
                ControlResult::BindFailed => return ControlResult::PairFirstBindFailed,
                ControlResult::TimedOut => return ControlResult::PairFirstTimedOut,
                ControlResult::Rejected
                | ControlResult::PairSucceeded
                | ControlResult::PairFirstBindFailed
                | ControlResult::PairFirstFailed
                | ControlResult::PairFirstTimedOut
                | ControlResult::PairSecondFailed
                | ControlResult::PairCancellationSucceeded
                | ControlResult::PairCancellationFailed => {
                    return ControlResult::PairFirstFailed;
                }
                ControlResult::MasterDied => return ControlResult::MasterDied,
            }
            let second = runner.run(&authority.invocation("forward", pair.ipv6), timeout);
            if second == ControlResult::Succeeded {
                ControlResult::PairSucceeded
            } else if second == ControlResult::MasterDied {
                ControlResult::MasterDied
            } else {
                let rollback = runner.run(&authority.invocation("cancel", pair.ipv4), timeout);
                if rollback == ControlResult::MasterDied {
                    ControlResult::MasterDied
                } else {
                    ControlResult::PairSecondFailed
                }
            }
        }
        ControlOperation::CancelPair(pair) => {
            let ipv4 = runner.run(&authority.invocation("cancel", pair.ipv4), timeout);
            let ipv6 = runner.run(&authority.invocation("cancel", pair.ipv6), timeout);
            if ipv4 == ControlResult::MasterDied || ipv6 == ControlResult::MasterDied {
                ControlResult::MasterDied
            } else if ipv4 == ControlResult::Succeeded && ipv6 == ControlResult::Succeeded {
                ControlResult::PairCancellationSucceeded
            } else {
                ControlResult::PairCancellationFailed
            }
        }
    }
}

impl Drop for ControlWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::forwarding::protocol::{CorrelationId, ForwardSpec, LoopbackAddress};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn spec(port: u16) -> ForwardSpec {
        ForwardSpec {
            local_address: LoopbackAddress::Ipv4([127, 0, 0, 1]),
            local_port: port,
            remote_address: LoopbackAddress::Ipv6,
            remote_port: 443,
        }
    }

    #[test]
    fn control_invocation_is_structured_and_contains_one_exact_forward() {
        let authority =
            ControlAuthority::new("user@remote".to_string(), PathBuf::from("/private/ctl"));

        let invocation = authority.invocation("forward", spec(8443));

        assert_eq!(invocation.program, "ssh");
        assert_eq!(
            invocation.args,
            vec![
                "-F",
                "/dev/null",
                "-S",
                "/private/ctl",
                "-O",
                "forward",
                "-L",
                "127.0.0.1:8443:[::1]:443",
                "user@remote",
            ]
        );
    }

    struct SerialProbe {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl CommandRunner for SerialProbe {
        fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(40));
            self.active.fetch_sub(1, Ordering::SeqCst);
            ControlResult::Succeeded
        }

        fn cancel(&self) {}
    }

    #[test]
    fn atomic_pair_creates_ipv4_then_ipv6_and_rolls_back_ipv4_once() {
        struct PairRunner {
            operations: std::sync::Mutex<Vec<(String, String)>>,
            results: std::sync::Mutex<std::collections::VecDeque<ControlResult>>,
        }

        impl CommandRunner for PairRunner {
            fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                let operation = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-O").then(|| args[1].clone()))
                    .expect("operation");
                let specification = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-L").then(|| args[1].clone()))
                    .expect("specification");
                self.operations
                    .lock()
                    .expect("operations")
                    .push((operation, specification));
                self.results
                    .lock()
                    .expect("results")
                    .pop_front()
                    .expect("queued result")
            }

            fn cancel(&self) {}
        }

        let pair = LocalhostPairSpec::new(8080, 3000).expect("valid pair");
        let runner = Arc::new(PairRunner {
            operations: std::sync::Mutex::new(Vec::new()),
            results: std::sync::Mutex::new(std::collections::VecDeque::from([
                ControlResult::Succeeded,
                ControlResult::Rejected,
                ControlResult::Rejected,
            ])),
        });
        let worker = ControlWorker::start(
            ControlAuthority::new("remote".to_string(), PathBuf::from("/ctl")),
            runner.clone(),
            Duration::from_secs(10),
        );

        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::ForwardPair(pair),
            })
            .expect("pair job");

        assert_eq!(
            worker.recv().expect("pair result").result,
            ControlResult::PairSecondFailed
        );
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec![
                (
                    "forward".to_string(),
                    "127.0.0.1:8080:127.0.0.1:3000".to_string()
                ),
                ("forward".to_string(), "[::1]:8080:[::1]:3000".to_string()),
                (
                    "cancel".to_string(),
                    "127.0.0.1:8080:127.0.0.1:3000".to_string()
                ),
            ]
        );
    }

    #[test]
    fn pair_cancellation_attempts_ipv6_after_ipv4_failure() {
        struct CancellationRunner {
            operations: std::sync::Mutex<Vec<String>>,
            results: std::sync::Mutex<std::collections::VecDeque<ControlResult>>,
        }

        impl CommandRunner for CancellationRunner {
            fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                let specification = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-L").then(|| args[1].clone()))
                    .expect("specification");
                self.operations
                    .lock()
                    .expect("operations")
                    .push(specification);
                self.results
                    .lock()
                    .expect("results")
                    .pop_front()
                    .expect("queued result")
            }

            fn cancel(&self) {}
        }

        let runner = Arc::new(CancellationRunner {
            operations: std::sync::Mutex::new(Vec::new()),
            results: std::sync::Mutex::new(std::collections::VecDeque::from([
                ControlResult::Rejected,
                ControlResult::TimedOut,
            ])),
        });
        let worker = ControlWorker::start(
            ControlAuthority::new("remote".to_string(), PathBuf::from("/ctl")),
            runner.clone(),
            Duration::from_secs(10),
        );
        let pair = LocalhostPairSpec::new(8080, 3000).expect("pair");
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::CancelPair(pair),
            })
            .expect("cancel pair");

        assert_eq!(
            worker.recv().expect("result").result,
            ControlResult::PairCancellationFailed
        );
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec![
                "127.0.0.1:8080:127.0.0.1:3000".to_string(),
                "[::1]:8080:[::1]:3000".to_string(),
            ]
        );
    }

    #[test]
    fn dropping_control_worker_cancels_and_reaps_the_active_command() {
        struct CancellableRunner {
            started: mpsc::SyncSender<()>,
            cancelled: AtomicBool,
            reaped: mpsc::SyncSender<()>,
        }

        impl CommandRunner for CancellableRunner {
            fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                let _ = self.started.send(());
                while !self.cancelled.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let _ = self.reaped.send(());
                ControlResult::Rejected
            }

            fn cancel(&self) {
                self.cancelled.store(true, Ordering::Release);
            }
        }

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (reaped_tx, reaped_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(CancellableRunner {
            started: started_tx,
            cancelled: AtomicBool::new(false),
            reaped: reaped_tx,
        });
        let worker = ControlWorker::start(
            ControlAuthority::new("example".to_owned(), PathBuf::from("/tmp/control")),
            runner.clone(),
            Duration::from_secs(10),
        );
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::Forward(spec(8080)),
            })
            .expect("submit active command");
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("command started");

        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let drop_thread = std::thread::spawn(move || {
            drop(worker);
            let _ = dropped_tx.send(());
        });
        let prompt = dropped_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        if !prompt {
            runner.cancel();
        }
        drop_thread.join().expect("drop thread");

        assert!(prompt, "worker teardown waited on the command timeout");
        reaped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("active command reaped");
    }

    #[test]
    fn shutdown_fences_queued_run_before_runner_invocation_and_joins_promptly() {
        struct ShutdownRaceRunner {
            invocations: AtomicUsize,
            cancelled: mpsc::SyncSender<()>,
        }

        impl CommandRunner for ShutdownRaceRunner {
            fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                self.invocations.fetch_add(1, Ordering::SeqCst);
                ControlResult::Succeeded
            }

            fn cancel(&self) {
                let _ = self.cancelled.send(());
            }
        }

        let (worker_paused_tx, worker_paused_rx) = mpsc::sync_channel(1);
        let (release_worker_tx, release_worker_rx) = mpsc::sync_channel(1);
        let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(ShutdownRaceRunner {
            invocations: AtomicUsize::new(0),
            cancelled: cancelled_tx,
        });
        let mut worker = ControlWorker::start_with_hook(
            ControlAuthority::new("example".to_owned(), PathBuf::from("/tmp/control")),
            runner.clone(),
            Duration::from_secs(10),
            move || {
                let _ = worker_paused_tx.send(());
                let _ = release_worker_rx.recv();
            },
        );
        worker_paused_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker paused before receiving queued run");
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::Forward(spec(8080)),
            })
            .expect("submit queued run");

        let shutdown = std::thread::spawn(move || {
            let started = Instant::now();
            worker.shutdown();
            worker.shutdown();
            (worker, started.elapsed())
        });
        cancelled_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown fence set before runner cancellation");
        release_worker_tx.send(()).expect("release worker");
        let (worker, elapsed) = shutdown.join().expect("shutdown thread");

        assert!(elapsed < Duration::from_millis(100));
        assert_eq!(runner.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            worker.recv().expect("queued result").result,
            ControlResult::Rejected
        );
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_winning_before_process_admission_rejects_without_spawning() {
        let marker = std::env::temp_dir().join(format!(
            "herdr-worker-admission-race-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let invocation = ControlInvocation {
            program: "/usr/bin/touch".into(),
            args: vec![marker.to_string_lossy().into_owned()],
        };
        let (before_admission_tx, before_admission_rx) = mpsc::sync_channel(1);
        let (release_admission_tx, release_admission_rx) = mpsc::sync_channel(1);
        let release_admission_rx = Mutex::new(release_admission_rx);
        let (stopping_tx, stopping_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(ProcessCommandRunner::with_test_hooks(ProcessRunnerHooks {
            before_admission: Some(Arc::new(move || {
                let _ = before_admission_tx.send(());
                let _ = release_admission_rx
                    .lock()
                    .expect("release admission lock")
                    .recv();
            })),
            after_stopping: Some(Arc::new(move || {
                let _ = stopping_tx.send(());
            })),
            ..ProcessRunnerHooks::default()
        }));
        let mut worker = ControlWorker::start(
            ControlAuthority::with_test_invocation(invocation),
            runner,
            Duration::from_secs(10),
        );
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::Forward(spec(8080)),
            })
            .expect("submit command");
        before_admission_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker paused before lifecycle admission");

        let (shutdown_started_tx, shutdown_started_rx) = mpsc::sync_channel(1);
        let shutdown = std::thread::spawn(move || {
            let _ = shutdown_started_tx.send(());
            worker.shutdown();
            worker.shutdown();
            worker
        });
        shutdown_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown started");
        stopping_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown won lifecycle admission");
        let released = Instant::now();
        release_admission_tx.send(()).expect("release admission");
        let worker = shutdown.join().expect("shutdown thread");

        assert!(
            released.elapsed() < Duration::from_millis(500),
            "worker teardown waited on the command timeout"
        );
        assert_eq!(
            worker.recv().expect("rejected result").result,
            ControlResult::Rejected
        );
        assert!(
            !marker.exists(),
            "process side effect occurred after shutdown"
        );
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_waits_for_spawn_publication_then_terminates_and_reaps_that_child() {
        let (spawned_tx, spawned_rx) = mpsc::sync_channel(1);
        let (release_publication_tx, release_publication_rx) = mpsc::sync_channel(1);
        let release_publication_rx = Mutex::new(release_publication_rx);
        let (lifecycle_contended_tx, lifecycle_contended_rx) = mpsc::sync_channel(1);
        let (stopping_tx, stopping_rx) = mpsc::sync_channel(1);
        let (reaped_tx, reaped_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(ProcessCommandRunner::with_test_hooks(ProcessRunnerHooks {
            after_spawn_before_publication: Some(Arc::new(move |child_id| {
                let _ = spawned_tx.send(child_id);
                let _ = release_publication_rx
                    .lock()
                    .expect("release publication lock")
                    .recv();
            })),
            after_cancel_observed_lifecycle_contention: Some(Arc::new(move || {
                let _ = lifecycle_contended_tx.send(());
            })),
            after_stopping: Some(Arc::new(move || {
                let _ = stopping_tx.send(());
            })),
            after_reap: Some(Arc::new(move |child_id| {
                let _ = reaped_tx.send(child_id);
            })),
            ..ProcessRunnerHooks::default()
        }));
        let mut worker = ControlWorker::start(
            ControlAuthority::with_test_invocation(ControlInvocation {
                program: "/bin/sleep".into(),
                args: vec!["60".into()],
            }),
            runner,
            Duration::from_secs(10),
        );
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::Forward(spec(8080)),
            })
            .expect("submit command");
        let child_id = spawned_rx.recv().expect("child spawned before publication");

        let shutdown = std::thread::spawn(move || {
            worker.shutdown();
            worker
        });
        lifecycle_contended_rx
            .recv()
            .expect("shutdown observed lifecycle contention before publication");
        release_publication_tx
            .send(())
            .expect("release publication");

        stopping_rx
            .recv()
            .expect("shutdown latched after publication");
        assert_eq!(reaped_rx.recv().expect("published child reaped"), child_id);
        let worker = shutdown.join().expect("shutdown thread");
        assert_eq!(
            worker.recv().expect("cancelled result").result,
            ControlResult::Rejected
        );
        let child_id = child_id.to_string();
        assert!(
            !Command::new("ps")
                .args(["-p", child_id.as_str(), "-o", "pid="])
                .stdout(Stdio::null())
                .status()
                .expect("inspect child process")
                .success(),
            "spawned child still exists after reap"
        );
    }

    #[test]
    fn control_worker_serializes_all_commands() {
        let probe = Arc::new(SerialProbe {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let authority = ControlAuthority::new("remote".to_string(), PathBuf::from("/ctl"));
        let worker = ControlWorker::start(authority, probe.clone(), Duration::from_secs(10));

        worker
            .submit(WorkerJob {
                id: CorrelationId::new(1).expect("id"),
                operation: ControlOperation::Forward(spec(8000)),
            })
            .expect("first job");
        worker
            .submit(WorkerJob {
                id: CorrelationId::new(2).expect("id"),
                operation: ControlOperation::Cancel(spec(8001)),
            })
            .expect("second job");

        assert_eq!(
            worker.recv().expect("first result").result,
            ControlResult::Succeeded
        );
        assert_eq!(
            worker.recv().expect("second result").result,
            ControlResult::Succeeded
        );
        assert_eq!(probe.max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retryable_bind_failures_require_unambiguous_openssh_listener_collision_evidence() {
        for stderr in [
            "bind [127.0.0.1]:80: Address already in use",
            "bind [::1]:8080: address already in use\r\nCould not request local forwarding.",
        ] {
            assert_eq!(
                classify_openssh_control_stderr(stderr),
                OpenSshControlFailure::BindCollision,
                "stderr: {stderr:?}"
            );
        }

        for stderr in [
            "bind [127.0.0.1]:80: Permission denied",
            "Control socket connect(/tmp/herdr-ctl): Permission denied",
            "user@remote: Permission denied (publickey).",
            "open /private/ctl: Permission denied",
            "bind [::1]:8080: Adresse bereits verwendet",
            "debug noise: Address already in use",
            "Address already in use",
            "",
            "Could not request local forwarding.",
            "mux_client_request_session: master session id: 2",
        ] {
            assert_eq!(
                classify_openssh_control_stderr(stderr),
                OpenSshControlFailure::Rejected,
                "stderr: {stderr:?}"
            );
        }

        for stderr in [
            "Control socket connect(/tmp/herdr-ctl): No such file or directory",
            "Control socket connect(/tmp/herdr-ctl): Connection refused",
            "mux_client_request_alive: master is not running",
        ] {
            assert_eq!(
                classify_openssh_control_stderr(stderr),
                OpenSshControlFailure::MasterDied,
                "stderr: {stderr:?}"
            );
        }
    }

    #[test]
    fn process_runner_terminates_and_reaps_a_timed_out_child() {
        let runner = ProcessCommandRunner::default();
        let invocation = ControlInvocation {
            program: "/bin/sleep".into(),
            args: vec!["60".into()],
        };
        let started = Instant::now();

        let result = runner.run(&invocation, Duration::from_millis(30));

        assert_eq!(result, ControlResult::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn process_runner_cancellation_terminates_and_reaps_the_active_child() {
        let runner = Arc::new(ProcessCommandRunner::default());
        let invocation = ControlInvocation {
            program: "/bin/sleep".into(),
            args: vec!["60".into()],
        };
        let command_runner = Arc::clone(&runner);
        let command =
            std::thread::spawn(move || command_runner.run(&invocation, Duration::from_secs(10)));
        let deadline = Instant::now() + Duration::from_secs(1);
        while !runner.has_active_child() {
            assert!(Instant::now() < deadline, "child did not start");
            std::thread::yield_now();
        }

        let started = Instant::now();
        runner.cancel();
        assert_eq!(
            command.join().expect("command thread"),
            ControlResult::Rejected
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!runner.has_active_child());
    }
}
