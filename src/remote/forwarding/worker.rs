use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
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
}

impl ControlAuthority {
    pub(crate) fn new(target: String, control_path: PathBuf) -> Self {
        Self {
            target,
            control_path,
        }
    }

    fn invocation(&self, operation_name: &'static str, spec: ForwardSpec) -> ControlInvocation {
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
}

pub(super) trait CommandRunner: Send + Sync + 'static {
    fn run(&self, invocation: &ControlInvocation, timeout: Duration) -> ControlResult;
}

pub(super) struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, invocation: &ControlInvocation, timeout: Duration) -> ControlResult {
        let mut child = match Command::new(&invocation.program)
            .args(&invocation.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return ControlResult::Rejected,
        };
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
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
                    };
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ControlResult::TimedOut;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ControlResult::Rejected;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenSshControlFailure {
    BindCollision,
    Rejected,
}

fn classify_openssh_control_stderr(stderr: &str) -> OpenSshControlFailure {
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
    thread: Option<JoinHandle<()>>,
}

impl ControlWorker {
    pub(super) fn start(
        authority: ControlAuthority,
        runner: Arc<dyn CommandRunner>,
        timeout: Duration,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let (result_sender, results) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            while let Ok(message) = receiver.recv() {
                match message {
                    WorkerMessage::Run(job) => {
                        let result =
                            run_operation(&authority, runner.as_ref(), job.operation, timeout);
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
            }
            let second = runner.run(&authority.invocation("forward", pair.ipv6), timeout);
            if second == ControlResult::Succeeded {
                ControlResult::PairSucceeded
            } else {
                let _ = runner.run(&authority.invocation("cancel", pair.ipv4), timeout);
                ControlResult::PairSecondFailed
            }
        }
        ControlOperation::CancelPair(pair) => {
            let ipv4 = runner.run(&authority.invocation("cancel", pair.ipv4), timeout);
            let ipv6 = runner.run(&authority.invocation("cancel", pair.ipv6), timeout);
            if ipv4 == ControlResult::Succeeded && ipv6 == ControlResult::Succeeded {
                ControlResult::PairCancellationSucceeded
            } else {
                ControlResult::PairCancellationFailed
            }
        }
    }
}

impl Drop for ControlWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerMessage::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::forwarding::protocol::{CorrelationId, ForwardSpec, LoopbackAddress};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
    }

    #[test]
    fn process_runner_terminates_and_reaps_a_timed_out_child() {
        let runner = ProcessCommandRunner;
        let invocation = ControlInvocation {
            program: "/bin/sleep".into(),
            args: vec!["60".into()],
        };
        let started = Instant::now();

        let result = runner.run(&invocation, Duration::from_millis(30));

        assert_eq!(result, ControlResult::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
