use std::io;
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

    fn invocation(&self, operation: ControlOperation) -> ControlInvocation {
        let (operation_name, spec) = match operation {
            ControlOperation::Forward(spec) => ("forward", spec),
            ControlOperation::Cancel(spec) => ("cancel", spec),
        };
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
pub(super) enum ControlOperation {
    Forward(ForwardSpec),
    Cancel(ForwardSpec),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlResult {
    Succeeded,
    Rejected,
    TimedOut,
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
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return ControlResult::Rejected,
        };
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        ControlResult::Succeeded
                    } else {
                        ControlResult::Rejected
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
                        let invocation = authority.invocation(job.operation);
                        let result = runner.run(&invocation, timeout);
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

        let invocation = authority.invocation(ControlOperation::Forward(spec(8443)));

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
