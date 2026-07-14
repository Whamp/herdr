use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use super::pair::{LocalhostMappings, PairRequest, PairSettlement};
use super::protocol::{
    self, ClientMessage, CorrelationId, ForwardFailure, ForwardSpec, ServerMessage,
    BROKER_PROTOCOL_VERSION,
};
use super::transport::AuthenticatedFrameReader;
use super::worker::{
    CommandRunner, ControlAuthority, ControlOperation, ControlResult, ControlWorker,
    PairControlResult, WorkerJob,
};

const MAX_PENDING_FORWARD_REQUESTS: usize = 32;

// Follow-up external-open routing consumes the established forward-call API.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Hello,
    Policy,
    Forward,
    Localhost,
}

struct PendingClientCall {
    kind: PendingKind,
    sender: mpsc::SyncSender<ServerMessage>,
}

struct ClientInner {
    writer: Mutex<UnixStream>,
    pending: Mutex<BTreeMap<u64, PendingClientCall>>,
    next_id: AtomicU64,
    active: AtomicBool,
    closed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct ForwardingClient {
    inner: Arc<ClientInner>,
}

// Follow-up external-open routing consumes these capability operations.
#[allow(dead_code)]
impl ForwardingClient {
    pub(super) fn from_stream(
        stream: UnixStream,
        initial_policy: bool,
        expected_parent: crate::platform::InheritedPeerIdentity,
    ) -> io::Result<Self> {
        let reader_stream = stream.try_clone()?;
        let inner = Arc::new(ClientInner {
            writer: Mutex::new(stream),
            pending: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        spawn_client_reader(reader_stream, expected_parent, Arc::downgrade(&inner))?;
        let client = Self { inner };
        let hello = client.call(PendingKind::Hello, |id| ClientMessage::Hello {
            id,
            version: BROKER_PROTOCOL_VERSION,
        })?;
        if !matches!(
            hello,
            ServerMessage::HelloAcknowledged {
                version: BROKER_PROTOCOL_VERSION,
                ..
            }
        ) {
            client.close();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forwarding broker hello rejected",
            ));
        }
        client.assert_policy(initial_policy)?;
        Ok(client)
    }

    #[cfg(test)]
    pub(super) fn raw_descriptor_for_test(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;

        self.inner
            .writer
            .lock()
            .map(|writer| writer.as_raw_fd())
            .unwrap_or(-1)
    }

    #[cfg(test)]
    fn from_stream_for_test(stream: UnixStream, initial_policy: bool) -> io::Result<Self> {
        Self::from_stream(
            stream,
            initial_policy,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::Acquire) && !self.inner.closed.load(Ordering::Acquire)
    }

    pub(crate) fn assert_policy(&self, enabled: bool) -> io::Result<()> {
        let (effective, result) = self.begin_assert_policy(enabled)?.wait()?;
        self.inner.active.store(effective, Ordering::Release);
        result.map_err(|_| io::Error::other("forwarding broker policy update failed"))
    }

    pub(crate) fn begin_assert_policy(&self, enabled: bool) -> io::Result<PolicyCall> {
        let (_id, receiver) = self.start_call(PendingKind::Policy, |id| {
            ClientMessage::AssertPolicy { id, enabled }
        })?;
        Ok(PolicyCall {
            requested: enabled,
            receiver: Some(receiver),
            inner: Arc::clone(&self.inner),
            settled: false,
        })
    }

    pub(crate) fn begin_forward(&self, spec: ForwardSpec) -> Result<ForwardCall, ForwardFailure> {
        self.begin_mapping_call(PendingKind::Forward, |id| ClientMessage::Forward {
            id,
            spec,
        })
    }

    pub(crate) fn begin_localhost(
        &self,
        remote_port: u16,
    ) -> Result<LocalhostCall, ForwardFailure> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ForwardFailure::CapabilityClosed);
        }
        let (id, receiver) = self
            .start_call(PendingKind::Localhost, |id| {
                ClientMessage::ForwardLocalhost { id, remote_port }
            })
            .map_err(|_| {
                self.close();
                ForwardFailure::CapabilityClosed
            })?;
        Ok(LocalhostCall {
            id,
            receiver: Some(receiver),
            inner: Arc::clone(&self.inner),
            settled: false,
            cancelled: false,
        })
    }

    fn begin_mapping_call(
        &self,
        kind: PendingKind,
        message: impl FnOnce(CorrelationId) -> ClientMessage,
    ) -> Result<ForwardCall, ForwardFailure> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ForwardFailure::CapabilityClosed);
        }
        let (id, receiver) = match self.start_call(kind, message) {
            Ok(call) => call,
            Err(_) => {
                self.close();
                return Err(ForwardFailure::CapabilityClosed);
            }
        };
        Ok(ForwardCall {
            id,
            receiver: Some(receiver),
            inner: Arc::clone(&self.inner),
            settled: false,
            cancelled: false,
        })
    }

    fn call(
        &self,
        kind: PendingKind,
        message: impl FnOnce(CorrelationId) -> ClientMessage,
    ) -> io::Result<ServerMessage> {
        let (_id, receiver) = match self.start_call(kind, message) {
            Ok(call) => call,
            Err(err) => {
                self.close();
                return Err(err);
            }
        };
        receiver
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "forwarding broker closed"))
    }

    fn start_call(
        &self,
        kind: PendingKind,
        message: impl FnOnce(CorrelationId) -> ClientMessage,
    ) -> io::Result<(CorrelationId, mpsc::Receiver<ServerMessage>)> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("forwarding writer unavailable"))?;
        let id = self.next_id()?;
        let receiver = self.insert_pending(id, kind)?;
        if let Err(err) = protocol::write_message(&mut *writer, &message(id)) {
            remove_pending(&self.inner, id);
            return Err(err);
        }
        Ok((id, receiver))
    }

    fn next_id(&self) -> io::Result<CorrelationId> {
        let value = self
            .inner
            .next_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| io::Error::other("forwarding correlation IDs exhausted"))?;
        CorrelationId::new(value)
            .ok_or_else(|| io::Error::other("forwarding correlation IDs exhausted"))
    }

    fn insert_pending(
        &self,
        id: CorrelationId,
        kind: PendingKind,
    ) -> io::Result<mpsc::Receiver<ServerMessage>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut pending = self
            .inner
            .pending
            .lock()
            .map_err(|_| io::Error::other("forwarding pending state unavailable"))?;
        if pending
            .insert(id.get(), PendingClientCall { kind, sender })
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate forwarding correlation ID",
            ));
        }
        Ok(receiver)
    }

    fn send(&self, message: &ClientMessage) -> io::Result<()> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("forwarding writer unavailable"))?;
        protocol::write_message(&mut *writer, message)
    }

    fn cancel(&self, id: CorrelationId) {
        if !self.inner.closed.load(Ordering::Acquire) {
            let _ = self.send(&ClientMessage::Cancel { id });
        }
    }

    fn close(&self) {
        close_client_inner(&self.inner);
    }
}

// Follow-up external-open routing retains this cancellable call handle.
#[allow(dead_code)]
impl Drop for ForwardingClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            close_client_inner(&self.inner);
        }
    }
}

pub(crate) struct ForwardCall {
    id: CorrelationId,
    receiver: Option<mpsc::Receiver<ServerMessage>>,
    inner: Arc<ClientInner>,
    settled: bool,
    cancelled: bool,
}

impl ForwardCall {
    #[cfg(test)]
    pub(crate) fn wait(mut self) -> Result<(), ForwardFailure> {
        let response = self
            .receiver
            .take()
            .and_then(|receiver| receiver.recv().ok());
        self.settled = true;
        forward_response(response)
    }

    pub(crate) fn try_wait(&mut self) -> Option<Result<(), ForwardFailure>> {
        let response = match self.receiver.as_ref()?.try_recv() {
            Ok(response) => response,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.receiver = None;
                self.settled = true;
                return Some(Err(ForwardFailure::CapabilityClosed));
            }
        };
        self.receiver = None;
        self.settled = true;
        Some(forward_response(Some(response)))
    }

    pub(crate) fn cancel(&mut self) {
        if self.settled || self.cancelled {
            return;
        }
        let client = ForwardingClient {
            inner: Arc::clone(&self.inner),
        };
        client.cancel(self.id);
        self.cancelled = true;
    }
}

fn forward_response(response: Option<ServerMessage>) -> Result<(), ForwardFailure> {
    match response {
        Some(ServerMessage::ForwardSettled { result, .. }) => result,
        Some(ServerMessage::Cancelled { .. }) => Err(ForwardFailure::Cancelled),
        _ => Err(ForwardFailure::CapabilityClosed),
    }
}

impl Drop for ForwardCall {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) struct LocalhostCall {
    id: CorrelationId,
    receiver: Option<mpsc::Receiver<ServerMessage>>,
    inner: Arc<ClientInner>,
    settled: bool,
    cancelled: bool,
}

impl LocalhostCall {
    #[cfg(test)]
    pub(crate) fn wait(mut self) -> Result<u16, ForwardFailure> {
        let response = self
            .receiver
            .take()
            .and_then(|receiver| receiver.recv().ok());
        self.settled = true;
        localhost_response(response)
    }

    pub(crate) fn try_wait(&mut self) -> Option<Result<u16, ForwardFailure>> {
        let response = match self.receiver.as_ref()?.try_recv() {
            Ok(response) => response,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.receiver = None;
                self.settled = true;
                return Some(Err(ForwardFailure::CapabilityClosed));
            }
        };
        self.receiver = None;
        self.settled = true;
        Some(localhost_response(Some(response)))
    }

    pub(crate) fn cancel(&mut self) {
        if self.settled || self.cancelled {
            return;
        }
        ForwardingClient {
            inner: Arc::clone(&self.inner),
        }
        .cancel(self.id);
        self.cancelled = true;
    }
}

fn localhost_response(response: Option<ServerMessage>) -> Result<u16, ForwardFailure> {
    match response {
        Some(ServerMessage::ForwardLocalhostSettled { result, .. }) => result,
        Some(ServerMessage::Cancelled { .. }) => Err(ForwardFailure::Cancelled),
        _ => Err(ForwardFailure::CapabilityClosed),
    }
}

impl Drop for LocalhostCall {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(crate) struct PolicyCall {
    requested: bool,
    receiver: Option<mpsc::Receiver<ServerMessage>>,
    inner: Arc<ClientInner>,
    settled: bool,
}

impl PolicyCall {
    fn wait(mut self) -> io::Result<(bool, Result<(), ForwardFailure>)> {
        let response = self
            .receiver
            .take()
            .and_then(|receiver| receiver.recv().ok());
        self.settled = true;
        let settled = policy_response(self.requested, response)?;
        self.inner.active.store(settled.0, Ordering::Release);
        Ok(settled)
    }

    pub(crate) fn try_wait(&mut self) -> Option<(bool, Result<(), ForwardFailure>)> {
        let response = match self.receiver.as_ref()?.try_recv() {
            Ok(response) => response,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.receiver = None;
                self.settled = true;
                return Some((false, Err(ForwardFailure::CapabilityClosed)));
            }
        };
        self.receiver = None;
        self.settled = true;
        let settled = policy_response(self.requested, Some(response))
            .unwrap_or((false, Err(ForwardFailure::CapabilityClosed)));
        self.inner.active.store(settled.0, Ordering::Release);
        Some(settled)
    }

    pub(crate) fn cancel(&mut self) {
        self.receiver = None;
        self.settled = true;
    }
}

fn policy_response(
    requested: bool,
    response: Option<ServerMessage>,
) -> io::Result<(bool, Result<(), ForwardFailure>)> {
    match response {
        Some(ServerMessage::PolicyAcknowledged {
            requested: acknowledged,
            effective,
            result,
            ..
        }) if acknowledged == requested => Ok((effective, result)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forwarding broker policy acknowledgement rejected",
        )),
    }
}

impl Drop for PolicyCall {
    fn drop(&mut self) {
        if !self.settled {
            self.cancel();
        }
        let _ = &self.inner;
    }
}

fn spawn_client_reader(
    stream: UnixStream,
    expected: crate::platform::InheritedPeerIdentity,
    inner: Weak<ClientInner>,
) -> io::Result<()> {
    let mut reader = AuthenticatedFrameReader::new(stream, expected)?;
    std::thread::spawn(move || loop {
        let message = match reader.read_message::<ServerMessage>() {
            Ok(message) => message,
            Err(_) => {
                if let Some(inner) = inner.upgrade() {
                    close_client_inner(&inner);
                }
                break;
            }
        };
        let Some(inner) = inner.upgrade() else {
            break;
        };
        let id = message.correlation_id().get();
        let call = inner
            .pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&id));
        let Some(call) = call else {
            close_client_inner(&inner);
            break;
        };
        if !response_matches(call.kind, &message) {
            close_client_inner(&inner);
            break;
        }
        let _ = call.sender.send(message);
    });
    Ok(())
}

fn response_matches(kind: PendingKind, message: &ServerMessage) -> bool {
    matches!(
        (kind, message),
        (PendingKind::Hello, ServerMessage::HelloAcknowledged { .. })
            | (
                PendingKind::Policy,
                ServerMessage::PolicyAcknowledged { .. }
            )
            | (PendingKind::Forward, ServerMessage::ForwardSettled { .. })
            | (PendingKind::Forward, ServerMessage::Cancelled { .. })
            | (
                PendingKind::Localhost,
                ServerMessage::ForwardLocalhostSettled { .. }
            )
            | (PendingKind::Localhost, ServerMessage::Cancelled { .. })
    )
}

fn remove_pending(inner: &ClientInner, id: CorrelationId) {
    if let Ok(mut pending) = inner.pending.lock() {
        pending.remove(&id.get());
    }
}

fn close_client_inner(inner: &ClientInner) {
    if inner.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    inner.active.store(false, Ordering::Release);
    if let Ok(writer) = inner.writer.lock() {
        let _ = writer.shutdown(std::net::Shutdown::Both);
    }
    if let Ok(mut pending) = inner.pending.lock() {
        pending.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerState {
    AwaitHello,
    AwaitPolicy,
    Disabled,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadyMapping {
    pub(super) spec: ForwardSpec,
}

#[derive(Default)]
pub(super) struct MappingRegistry {
    ready: BTreeMap<ForwardSpec, ReadyMapping>,
}

impl MappingRegistry {
    fn owns_destination(&self, spec: ForwardSpec) -> bool {
        self.ready
            .keys()
            .any(|owned| same_destination(*owned, spec))
    }

    fn insert_ready(&mut self, spec: ForwardSpec) {
        self.ready.insert(spec, ReadyMapping { spec });
    }

    fn collides_with_ready(&self, spec: ForwardSpec) -> bool {
        self.ready.keys().any(|ready| {
            ready.local_address == spec.local_address
                && ready.local_port == spec.local_port
                && *ready != spec
        })
    }
}

fn same_destination(left: ForwardSpec, right: ForwardSpec) -> bool {
    left.remote_address == right.remote_address && left.remote_port == right.remote_port
}

#[derive(Debug, Clone, Copy)]
struct QueuedJob {
    job: WorkerJob,
    respond: bool,
}

pub(crate) struct BrokerServer {
    control: UnixStream,
    thread: Option<JoinHandle<()>>,
}

impl BrokerServer {
    pub(super) fn start(
        stream: UnixStream,
        expected_child: crate::platform::InheritedPeerIdentity,
        authority: ControlAuthority,
    ) -> io::Result<Self> {
        Self::start_with_runner(
            stream,
            expected_child,
            authority,
            Arc::new(super::worker::ProcessCommandRunner),
            super::worker::CONTROL_COMMAND_TIMEOUT,
        )
    }

    fn start_with_runner(
        stream: UnixStream,
        expected_child: crate::platform::InheritedPeerIdentity,
        authority: ControlAuthority,
        runner: Arc<dyn CommandRunner>,
        timeout: Duration,
    ) -> io::Result<Self> {
        let control = stream.try_clone()?;
        let thread_control = stream.try_clone()?;
        let thread = std::thread::spawn(move || {
            run_broker(stream, expected_child, authority, runner, timeout);
            let _ = thread_control.shutdown(std::net::Shutdown::Both);
        });
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    #[cfg(test)]
    pub(super) fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let _ = self.control.shutdown(std::net::Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for BrokerServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// Tickets 35 and 36 own when cleanup runs; this hook preserves pair-wide exact cancellation.
#[allow(dead_code)]
fn ready_pair_cancellation_operations(mappings: &LocalhostMappings) -> Vec<ControlOperation> {
    mappings
        .ready_pairs_least_recently_used()
        .into_iter()
        .map(ControlOperation::CancelPair)
        .collect()
}

fn run_broker(
    mut stream: UnixStream,
    expected_child: crate::platform::InheritedPeerIdentity,
    authority: ControlAuthority,
    runner: Arc<dyn CommandRunner>,
    timeout: Duration,
) {
    let reader_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let mut reader = match AuthenticatedFrameReader::new(reader_stream, expected_child) {
        Ok(reader) => reader,
        Err(_) => return,
    };
    let (message_sender, message_receiver) = mpsc::channel();
    std::thread::spawn(move || loop {
        let message = reader.read_message::<ClientMessage>();
        let failed = message.is_err();
        if message_sender.send(message).is_err() || failed {
            break;
        }
    });

    let worker = ControlWorker::start(authority, runner, timeout);
    let mut state = BrokerState::AwaitHello;
    let mut highest_id = 0_u64;
    let mut live = BTreeMap::<u64, ForwardSpec>::new();
    let mut mappings = MappingRegistry::default();
    let mut localhost = LocalhostMappings::default();
    let mut queue = VecDeque::<QueuedJob>::new();
    let mut active: Option<QueuedJob> = None;
    let mut pending_disable_ack = None;

    'broker: loop {
        while let Ok(result) = worker.try_recv() {
            let Some(completed) = active.take() else {
                break 'broker;
            };
            if completed.job.id != result.id || completed.job.operation != result.operation {
                break 'broker;
            }

            match completed.job.operation {
                ControlOperation::ForwardPair(pair) => {
                    let Some(pair_result) = PairControlResult::from_control(result.result) else {
                        break 'broker;
                    };
                    let completion = localhost.complete(pair, pair_result);
                    if let Some(next) = completion.command {
                        queue.push_front(QueuedJob {
                            job: WorkerJob {
                                id: completed.job.id,
                                operation: ControlOperation::ForwardPair(next),
                            },
                            respond: false,
                        });
                    } else if let Some(cancel) = completion.cancellation {
                        queue.push_front(QueuedJob {
                            job: WorkerJob {
                                id: completed.job.id,
                                operation: ControlOperation::CancelPair(cancel),
                            },
                            respond: false,
                        });
                    }
                    for settlement in completion.settlements {
                        if write_pair_settlement(&mut stream, settlement).is_err() {
                            break 'broker;
                        }
                    }
                }
                ControlOperation::CancelPair(_) => {}
                ControlOperation::Forward(_) | ControlOperation::Cancel(_) => {
                    if completed.respond {
                        live.remove(&result.id.get());
                        let scalar_result = match result.result {
                            ControlResult::Succeeded => {
                                if let ControlOperation::Forward(spec) = completed.job.operation {
                                    mappings.insert_ready(spec);
                                }
                                Ok(())
                            }
                            ControlResult::BindFailed => Err(ForwardFailure::BindFailed),
                            ControlResult::Rejected => Err(ForwardFailure::CommandRejected),
                            ControlResult::TimedOut => Err(ForwardFailure::CommandTimedOut),
                            ControlResult::PairSucceeded
                            | ControlResult::PairFirstBindFailed
                            | ControlResult::PairFirstFailed
                            | ControlResult::PairFirstTimedOut
                            | ControlResult::PairSecondFailed
                            | ControlResult::PairCancellationSucceeded
                            | ControlResult::PairCancellationFailed => break 'broker,
                        };
                        if protocol::write_message(
                            &mut stream,
                            &ServerMessage::ForwardSettled {
                                id: completed.job.id,
                                result: scalar_result,
                            },
                        )
                        .is_err()
                        {
                            break 'broker;
                        }
                    } else if result.result == ControlResult::Succeeded {
                        if let ControlOperation::Forward(spec) = completed.job.operation {
                            queue.push_front(QueuedJob {
                                job: WorkerJob {
                                    id: completed.job.id,
                                    operation: ControlOperation::Cancel(spec),
                                },
                                respond: false,
                            });
                        }
                    }
                }
            }
            if dispatch_next(&worker, &mut queue, &mut active).is_err() {
                break 'broker;
            }
            if active.is_none() {
                if let Some(id) = pending_disable_ack.take() {
                    if protocol::write_message(
                        &mut stream,
                        &ServerMessage::PolicyAcknowledged {
                            id,
                            requested: false,
                            effective: false,
                            result: Ok(()),
                        },
                    )
                    .is_err()
                    {
                        break 'broker;
                    }
                }
            }
        }

        match message_receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(Ok(message)) => {
                let id = message.correlation_id();
                if !matches!(message, ClientMessage::Cancel { .. }) {
                    if id.get() <= highest_id {
                        break 'broker;
                    }
                    highest_id = id.get();
                }
                match message {
                    ClientMessage::Hello { id, version }
                        if state == BrokerState::AwaitHello
                            && version == BROKER_PROTOCOL_VERSION =>
                    {
                        state = BrokerState::AwaitPolicy;
                        if protocol::write_message(
                            &mut stream,
                            &ServerMessage::HelloAcknowledged {
                                id,
                                version: BROKER_PROTOCOL_VERSION,
                            },
                        )
                        .is_err()
                        {
                            break 'broker;
                        }
                    }
                    ClientMessage::AssertPolicy { id, enabled }
                        if state != BrokerState::AwaitHello && pending_disable_ack.is_none() =>
                    {
                        if enabled {
                            state = BrokerState::Active;
                            if protocol::write_message(
                                &mut stream,
                                &ServerMessage::PolicyAcknowledged {
                                    id,
                                    requested: true,
                                    effective: true,
                                    result: Ok(()),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                        } else {
                            state = BrokerState::Disabled;
                            cancel_uncommitted(&mut stream, &mut live, &mut queue, &mut active);
                            localhost.revoke_creating();
                            if active.is_none() {
                                let _ = dispatch_next(&worker, &mut queue, &mut active);
                            }
                            if active.is_some() {
                                pending_disable_ack = Some(id);
                            } else if protocol::write_message(
                                &mut stream,
                                &ServerMessage::PolicyAcknowledged {
                                    id,
                                    requested: false,
                                    effective: false,
                                    result: Ok(()),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                        }
                    }
                    ClientMessage::Forward { id, spec }
                        if matches!(state, BrokerState::Disabled | BrokerState::Active)
                            && spec.is_valid() =>
                    {
                        if state == BrokerState::Disabled {
                            if protocol::write_message(
                                &mut stream,
                                &ServerMessage::ForwardSettled {
                                    id,
                                    result: Err(ForwardFailure::Disabled),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if live.values().any(|owned| same_destination(*owned, spec))
                            || mappings.owns_destination(spec)
                        {
                            if protocol::write_message(
                                &mut stream,
                                &ServerMessage::ForwardSettled {
                                    id,
                                    result: Err(ForwardFailure::AlreadyOwned),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if mappings.collides_with_ready(spec) {
                            if protocol::write_message(
                                &mut stream,
                                &ServerMessage::ForwardSettled {
                                    id,
                                    result: Err(ForwardFailure::BindFailed),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if live.len() >= MAX_PENDING_FORWARD_REQUESTS {
                            if protocol::write_message(
                                &mut stream,
                                &ServerMessage::ForwardSettled {
                                    id,
                                    result: Err(ForwardFailure::TooManyRequests),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        live.insert(id.get(), spec);
                        queue.push_back(QueuedJob {
                            job: WorkerJob {
                                id,
                                operation: ControlOperation::Forward(spec),
                            },
                            respond: true,
                        });
                        if dispatch_next(&worker, &mut queue, &mut active).is_err() {
                            break 'broker;
                        }
                    }
                    ClientMessage::ForwardLocalhost { id, remote_port }
                        if matches!(state, BrokerState::Disabled | BrokerState::Active)
                            && remote_port != 0 =>
                    {
                        if state == BrokerState::Disabled {
                            if write_pair_settlement(
                                &mut stream,
                                PairSettlement {
                                    id,
                                    result: Err(ForwardFailure::Disabled),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if live.len() + localhost.waiter_count() >= MAX_PENDING_FORWARD_REQUESTS {
                            if write_pair_settlement(
                                &mut stream,
                                PairSettlement {
                                    id,
                                    result: Err(ForwardFailure::TooManyRequests),
                                },
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        match localhost.request(id, remote_port) {
                            PairRequest::Ready(settlement) | PairRequest::Failed(settlement) => {
                                if write_pair_settlement(&mut stream, settlement).is_err() {
                                    break 'broker;
                                }
                            }
                            PairRequest::Pending { command } => {
                                if let Some(pair) = command {
                                    queue.push_back(QueuedJob {
                                        job: WorkerJob {
                                            id,
                                            operation: ControlOperation::ForwardPair(pair),
                                        },
                                        respond: false,
                                    });
                                    if dispatch_next(&worker, &mut queue, &mut active).is_err() {
                                        break 'broker;
                                    }
                                }
                            }
                        }
                    }
                    ClientMessage::Cancel { id } if state != BrokerState::AwaitHello => {
                        if localhost.cancel_waiter(id) {
                            let _ = protocol::write_message(
                                &mut stream,
                                &ServerMessage::Cancelled { id },
                            );
                        } else {
                            cancel_one(&mut stream, id, &mut live, &mut queue, &mut active);
                        }
                    }
                    _ => break 'broker,
                }
            }
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => break 'broker,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    cleanup_on_disconnect(&worker, &mut stream, &mut live, &mut queue, &mut active);
    localhost.reset();
}

fn write_pair_settlement(stream: &mut UnixStream, settlement: PairSettlement) -> io::Result<()> {
    protocol::write_message(
        stream,
        &ServerMessage::ForwardLocalhostSettled {
            id: settlement.id,
            result: settlement.result,
        },
    )
}

fn cleanup_on_disconnect(
    worker: &ControlWorker,
    stream: &mut UnixStream,
    live: &mut BTreeMap<u64, ForwardSpec>,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
) {
    cancel_uncommitted(stream, live, queue, active);
    if active.is_none() {
        let _ = dispatch_next(worker, queue, active);
    }
    while let Some(completed) = active.take() {
        let Ok(result) = worker.recv() else {
            break;
        };
        if result.id != completed.job.id || result.operation != completed.job.operation {
            break;
        }
        if result.result == ControlResult::Succeeded {
            if let ControlOperation::Forward(spec) = completed.job.operation {
                queue.push_front(QueuedJob {
                    job: WorkerJob {
                        id: completed.job.id,
                        operation: ControlOperation::Cancel(spec),
                    },
                    respond: false,
                });
            }
        }
        if dispatch_next(worker, queue, active).is_err() {
            break;
        }
    }
}

fn dispatch_next(
    worker: &ControlWorker,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
) -> io::Result<()> {
    if active.is_none() {
        if let Some(next) = queue.pop_front() {
            worker.submit(next.job)?;
            *active = Some(next);
        }
    }
    Ok(())
}

fn cancel_one(
    stream: &mut UnixStream,
    id: CorrelationId,
    live: &mut BTreeMap<u64, ForwardSpec>,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
) {
    if live.remove(&id.get()).is_none() {
        return;
    }
    if let Some(position) = queue.iter().position(|queued| queued.job.id == id) {
        queue.remove(position);
    }
    if let Some(running) = active.as_mut().filter(|running| running.job.id == id) {
        running.respond = false;
    }
    let _ = protocol::write_message(stream, &ServerMessage::Cancelled { id });
}

fn cancel_uncommitted(
    stream: &mut UnixStream,
    live: &mut BTreeMap<u64, ForwardSpec>,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
) {
    let ids = live
        .keys()
        .filter_map(|id| CorrelationId::new(*id))
        .collect::<Vec<_>>();
    for id in ids {
        cancel_one(stream, id, live, queue, active);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::forwarding::protocol::{LoopbackAddress, BROKER_PROTOCOL_VERSION};
    use crate::remote::forwarding::transport::AuthenticatedFrameReader;
    use crate::remote::forwarding::worker::{CommandRunner, ControlInvocation, ControlResult};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    struct CountingRunner {
        calls: AtomicUsize,
        delay: Duration,
    }

    struct RecordingRunner {
        operations: Mutex<Vec<String>>,
        results: Mutex<VecDeque<ControlResult>>,
        delay: Duration,
    }

    impl RecordingRunner {
        fn new(results: impl IntoIterator<Item = ControlResult>) -> Self {
            Self::with_delay(results, Duration::ZERO)
        }

        fn with_delay(results: impl IntoIterator<Item = ControlResult>, delay: Duration) -> Self {
            Self {
                operations: Mutex::new(Vec::new()),
                results: Mutex::new(results.into_iter().collect()),
                delay,
            }
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            let operation = invocation
                .args
                .windows(2)
                .find_map(|args| (args[0] == "-O").then(|| args[1].clone()))
                .expect("control operation");
            self.operations.lock().expect("operations").push(operation);
            std::thread::sleep(self.delay);
            self.results
                .lock()
                .expect("results")
                .pop_front()
                .expect("queued control result")
        }
    }

    impl CommandRunner for CountingRunner {
        fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            ControlResult::Succeeded
        }
    }

    fn spec() -> ForwardSpec {
        spec_for_port(8080)
    }

    fn spec_for_port(port: u16) -> ForwardSpec {
        spec_for_mapping(port, port)
    }

    fn spec_for_mapping(local_port: u16, remote_port: u16) -> ForwardSpec {
        ForwardSpec {
            local_address: LoopbackAddress::Ipv4([127, 0, 0, 1]),
            local_port,
            remote_address: LoopbackAddress::Ipv4([127, 0, 0, 1]),
            remote_port,
        }
    }

    fn authority() -> ControlAuthority {
        ControlAuthority::new(
            "secret-target".to_string(),
            PathBuf::from("/secret/control"),
        )
    }

    fn settle_forward(client: &ForwardingClient, spec: ForwardSpec) -> Result<(), ForwardFailure> {
        client.begin_forward(spec)?.wait()
    }

    #[test]
    fn broker_starts_disabled_and_activates_only_after_acknowledged_policy() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client =
            ForwardingClient::from_stream_for_test(child, false).expect("client handshake");

        assert!(!client.is_active());
        assert_eq!(
            settle_forward(&client, spec()),
            Err(ForwardFailure::Disabled)
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);

        client.assert_policy(true).expect("activate policy");
        assert!(client.is_active());
        assert_eq!(settle_forward(&client, spec()), Ok(()));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn creating_mapping_is_reported_as_owned_without_coalescing_or_another_command() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(80),
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        let first = client
            .begin_forward(spec_for_mapping(43_123, 8080))
            .expect("first forward");
        let repeated = client.begin_forward(spec()).expect("repeated destination");

        assert_eq!(repeated.wait(), Err(ForwardFailure::AlreadyOwned));
        assert_eq!(first.wait(), Ok(()));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ready_mapping_remains_owned_without_cleanup_on_disable() {
        let runner = Arc::new(RecordingRunner::new([ControlResult::Succeeded]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        assert_eq!(
            settle_forward(&client, spec_for_mapping(43_123, 8080)),
            Ok(())
        );
        assert_eq!(
            settle_forward(&client, spec()),
            Err(ForwardFailure::AlreadyOwned)
        );
        client.assert_policy(false).expect("disable policy");
        client.assert_policy(true).expect("re-enable policy");
        assert_eq!(
            settle_forward(&client, spec()),
            Err(ForwardFailure::AlreadyOwned)
        );

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward"]
        );
    }

    #[test]
    fn localhost_pair_is_ready_only_after_both_commands_and_reuses_one_mapping() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
        ]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        assert_eq!(client.begin_localhost(8080).expect("pair").wait(), Ok(8080));
        assert_eq!(
            client.begin_localhost(8080).expect("reuse").wait(),
            Ok(8080)
        );
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
        );
    }

    #[test]
    fn localhost_second_member_failure_rolls_back_once_and_returns_atomic_failure() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Rejected,
            ControlResult::Rejected,
        ]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        assert_eq!(
            client.begin_localhost(8080).expect("pair").wait(),
            Err(ForwardFailure::AtomicCreationFailed)
        );
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel"]
        );
    }

    #[test]
    fn cancelling_one_localhost_waiter_does_not_interrupt_the_pair_or_other_waiter() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [ControlResult::Succeeded, ControlResult::Succeeded],
            Duration::from_millis(60),
        ));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let first = client.begin_localhost(8080).expect("first waiter");
        let second = client.begin_localhost(8080).expect("second waiter");

        drop(first);

        assert_eq!(second.wait(), Ok(8080));
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
        );
    }

    #[test]
    fn cleanup_hook_returns_one_pair_wide_operation_per_saved_mapping_in_lru_order() {
        let mut mappings = LocalhostMappings::default();
        for (id, remote_port) in [(1, 8001), (2, 8002)] {
            let PairRequest::Pending {
                command: Some(pair),
            } = mappings.request(CorrelationId::new(id).expect("id"), remote_port)
            else {
                panic!("pair command");
            };
            mappings.complete(pair, PairControlResult::Succeeded);
        }
        assert!(matches!(
            mappings.request(CorrelationId::new(3).expect("id"), 8001),
            PairRequest::Ready(_)
        ));

        assert_eq!(
            ready_pair_cancellation_operations(&mappings)
                .into_iter()
                .map(|operation| match operation {
                    ControlOperation::CancelPair(pair) => pair.remote_port(),
                    _ => panic!("pair-wide cancellation operation"),
                })
                .collect::<Vec<_>>(),
            vec![8002, 8001]
        );
    }

    #[test]
    fn revoking_a_creating_localhost_pair_cancels_ipv4_then_ipv6_even_on_failures() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [
                ControlResult::Succeeded,
                ControlResult::Succeeded,
                ControlResult::Rejected,
                ControlResult::TimedOut,
            ],
            Duration::from_millis(40),
        ));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let pair = client.begin_localhost(8080).expect("pair");
        while runner.operations.lock().expect("operations").is_empty() {
            std::thread::yield_now();
        }
        drop(pair);

        client.assert_policy(false).expect("disable policy");

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "cancel"]
        );
    }

    #[test]
    fn attachment_disconnect_does_not_cancel_ready_localhost_pair_individually() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
        ]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        assert_eq!(client.begin_localhost(8080).expect("pair").wait(), Ok(8080));

        drop(client);
        broker.close();

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
        );
    }

    #[test]
    fn attachment_disconnect_does_not_cancel_ready_mappings_individually() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
        ]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        assert_eq!(settle_forward(&client, spec_for_port(8080)), Ok(()));
        assert_eq!(settle_forward(&client, spec_for_port(8081)), Ok(()));

        drop(client);
        broker.close();

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
        );
    }

    #[test]
    fn duplicate_monotonic_id_closes_the_entire_capability() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, mut child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let mut reader = AuthenticatedFrameReader::new(
            child.try_clone().expect("reader clone"),
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("reader");
        let id1 = CorrelationId::new(1).expect("id");
        protocol::write_message(
            &mut child,
            &ClientMessage::Hello {
                id: id1,
                version: BROKER_PROTOCOL_VERSION,
            },
        )
        .expect("hello");
        reader.read_message::<ServerMessage>().expect("hello ack");
        let id2 = CorrelationId::new(2).expect("id");
        protocol::write_message(
            &mut child,
            &ClientMessage::AssertPolicy {
                id: id2,
                enabled: true,
            },
        )
        .expect("policy");
        reader.read_message::<ServerMessage>().expect("policy ack");

        protocol::write_message(
            &mut child,
            &ClientMessage::Forward {
                id: id2,
                spec: spec(),
            },
        )
        .expect("duplicate id");

        assert!(reader.read_message::<ServerMessage>().is_err());
    }

    #[test]
    fn unknown_cancellation_is_a_benign_race() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, mut child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let mut reader = AuthenticatedFrameReader::new(
            child.try_clone().expect("reader clone"),
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("reader");
        for message in [
            ClientMessage::Hello {
                id: CorrelationId::new(1).expect("id"),
                version: BROKER_PROTOCOL_VERSION,
            },
            ClientMessage::AssertPolicy {
                id: CorrelationId::new(2).expect("id"),
                enabled: true,
            },
        ] {
            protocol::write_message(&mut child, &message).expect("handshake message");
            reader
                .read_message::<ServerMessage>()
                .expect("handshake ack");
        }
        protocol::write_message(
            &mut child,
            &ClientMessage::Cancel {
                id: CorrelationId::new(999).expect("id"),
            },
        )
        .expect("unknown cancel");
        protocol::write_message(
            &mut child,
            &ClientMessage::Forward {
                id: CorrelationId::new(3).expect("id"),
                spec: spec(),
            },
        )
        .expect("forward after cancel");

        assert!(matches!(
            reader
                .read_message::<ServerMessage>()
                .expect("forward result"),
            ServerMessage::ForwardSettled { result: Ok(()), .. }
        ));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_calls_keep_correlation_ids_in_stream_order() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let calls = (0..8)
            .map(|offset| {
                let client = client.clone();
                std::thread::spawn(move || settle_forward(&client, spec_for_port(8100 + offset)))
            })
            .collect::<Vec<_>>();

        for call in calls {
            assert_eq!(call.join().expect("call thread"), Ok(()));
        }
        assert_eq!(runner.calls.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn cancelling_a_queued_call_does_not_cancel_the_running_call() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(100),
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let running = client
            .begin_forward(spec_for_port(8080))
            .expect("running call");
        let queued = client
            .begin_forward(spec_for_port(8081))
            .expect("queued call");

        drop(queued);

        assert_eq!(running.wait(), Ok(()));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disable_acknowledgement_waits_for_in_flight_forward_cleanup() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(75),
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let call = client.begin_forward(spec()).expect("forward call");
        while runner.calls.load(Ordering::SeqCst) == 0 {
            std::thread::yield_now();
        }
        let policy_client = client.clone();
        let disable = std::thread::spawn(move || policy_client.assert_policy(false));

        assert_eq!(call.wait(), Err(ForwardFailure::Cancelled));
        disable
            .join()
            .expect("disable thread")
            .expect("disable ack");
        assert!(!client.is_active());
        assert_eq!(runner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn in_flight_cancellation_failure_does_not_change_disable_settlement() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [ControlResult::Succeeded, ControlResult::Rejected],
            Duration::from_millis(75),
        ));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let call = client.begin_forward(spec()).expect("forward call");
        while runner.operations.lock().expect("operations").is_empty() {
            std::thread::yield_now();
        }
        let policy_client = client.clone();
        let disable = std::thread::spawn(move || policy_client.assert_policy(false));

        assert_eq!(call.wait(), Err(ForwardFailure::Cancelled));
        disable
            .join()
            .expect("disable thread")
            .expect("disable remains confirmed");
        assert!(!client.is_active());
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "cancel"]
        );
    }

    #[test]
    fn channel_loss_fails_an_unresolved_forward_call() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(250),
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        let call = client.begin_forward(spec()).expect("begin forward");

        broker.close();

        assert_eq!(call.wait(), Err(ForwardFailure::CapabilityClosed));
    }

    #[test]
    fn truncated_half_closed_frame_closes_the_capability() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, mut child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let mut reader = AuthenticatedFrameReader::new(
            child.try_clone().expect("reader clone"),
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("reader");

        child.write_all(&2_u32.to_be_bytes()).expect("length");
        child.write_all(&[0]).expect("partial payload");
        child
            .shutdown(std::net::Shutdown::Write)
            .expect("half close");

        assert!(reader.read_message::<ServerMessage>().is_err());
    }

    #[test]
    fn malformed_oversized_frame_closes_the_capability() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        });
        let (parent, mut child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let mut reader = AuthenticatedFrameReader::new(
            child.try_clone().expect("reader clone"),
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("reader");

        child
            .write_all(&((protocol::MAX_PAYLOAD_BYTES + 1) as u32).to_be_bytes())
            .expect("oversized header");

        assert!(reader.read_message::<ServerMessage>().is_err());
    }
}
