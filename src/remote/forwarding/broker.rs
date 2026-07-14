use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use super::protocol::{
    self, ClientMessage, CorrelationId, ForwardFailure, ForwardSpec, ServerMessage,
    BROKER_PROTOCOL_VERSION,
};
use super::registry::{
    MappingAttempt, MappingCancellation, MappingControlResult, MappingRegistry, MappingRequest,
    MappingSettlement, SavedLimitChange, WaiterCancellation,
};
use super::transport::AuthenticatedFrameReader;
use super::worker::{CommandRunner, ControlAuthority, ControlResult, ControlWorker, WorkerJob};

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
    saved_mapping_limit: AtomicU8,
    closed: AtomicBool,
}

#[derive(Clone)]
pub(crate) struct ForwardingClient {
    inner: Arc<ClientInner>,
}

impl ForwardingClient {
    pub(super) fn from_stream(
        stream: UnixStream,
        initial_policy: bool,
        initial_saved_mapping_limit: crate::config::SavedPortForwardLimit,
        expected_parent: crate::platform::InheritedPeerIdentity,
    ) -> io::Result<Self> {
        let reader_stream = stream.try_clone()?;
        let inner = Arc::new(ClientInner {
            writer: Mutex::new(stream),
            pending: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            active: AtomicBool::new(false),
            saved_mapping_limit: AtomicU8::new(crate::config::SavedPortForwardLimit::DEFAULT.get()),
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
        client.assert_policy_with_limit(initial_policy, initial_saved_mapping_limit)?;
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
            crate::config::SavedPortForwardLimit::DEFAULT,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::Acquire) && !self.inner.closed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn assert_policy(&self, enabled: bool) -> io::Result<()> {
        self.assert_policy_with_limit(enabled, crate::config::SavedPortForwardLimit::DEFAULT)
    }

    pub(crate) fn assert_policy_with_limit(
        &self,
        enabled: bool,
        saved_mapping_limit: crate::config::SavedPortForwardLimit,
    ) -> io::Result<()> {
        let (effective, _effective_saved_mapping_limit, result) = self
            .begin_assert_policy(enabled, saved_mapping_limit)?
            .wait()?;
        self.inner.active.store(effective, Ordering::Release);
        result.map_err(|_| io::Error::other("forwarding broker policy update failed"))
    }

    pub(crate) fn begin_assert_policy(
        &self,
        enabled: bool,
        saved_mapping_limit: crate::config::SavedPortForwardLimit,
    ) -> io::Result<PolicyCall> {
        let (id, receiver) =
            self.start_call(PendingKind::Policy, |id| ClientMessage::AssertPolicy {
                id,
                enabled,
                saved_mapping_limit: saved_mapping_limit.get(),
            })?;
        Ok(PolicyCall {
            requested: enabled,
            requested_saved_mapping_limit: saved_mapping_limit,
            core: BrokerCallCore::new(
                id,
                receiver,
                Arc::clone(&self.inner),
                CancellationMode::LocalOnly,
            ),
        })
    }

    pub(crate) fn begin_forward(&self, spec: ForwardSpec) -> Result<MappingCall, ForwardFailure> {
        self.begin_mapping_call(PendingKind::Forward, MappingResponseKind::Scalar, |id| {
            ClientMessage::Forward { id, spec }
        })
    }

    pub(crate) fn begin_localhost(&self, remote_port: u16) -> Result<MappingCall, ForwardFailure> {
        self.begin_mapping_call(
            PendingKind::Localhost,
            MappingResponseKind::Localhost,
            |id| ClientMessage::ForwardLocalhost { id, remote_port },
        )
    }

    fn begin_mapping_call(
        &self,
        pending_kind: PendingKind,
        response_kind: MappingResponseKind,
        message: impl FnOnce(CorrelationId) -> ClientMessage,
    ) -> Result<MappingCall, ForwardFailure> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ForwardFailure::CapabilityClosed);
        }
        let (id, receiver) = match self.start_call(pending_kind, message) {
            Ok(call) => call,
            Err(_) => {
                self.close();
                return Err(ForwardFailure::CapabilityClosed);
            }
        };
        Ok(MappingCall {
            response_kind,
            core: BrokerCallCore::new(
                id,
                receiver,
                Arc::clone(&self.inner),
                CancellationMode::NotifyBroker,
            ),
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

impl Drop for ForwardingClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            close_client_inner(&self.inner);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationMode {
    NotifyBroker,
    LocalOnly,
}

struct BrokerCallCore {
    id: CorrelationId,
    receiver: Option<mpsc::Receiver<ServerMessage>>,
    inner: Arc<ClientInner>,
    cancellation_mode: CancellationMode,
    settled: bool,
    cancelled: bool,
}

impl BrokerCallCore {
    fn new(
        id: CorrelationId,
        receiver: mpsc::Receiver<ServerMessage>,
        inner: Arc<ClientInner>,
        cancellation_mode: CancellationMode,
    ) -> Self {
        Self {
            id,
            receiver: Some(receiver),
            inner,
            cancellation_mode,
            settled: false,
            cancelled: false,
        }
    }

    fn wait(&mut self) -> Result<ServerMessage, ForwardFailure> {
        let response = self
            .receiver
            .take()
            .and_then(|receiver| receiver.recv().ok())
            .ok_or(ForwardFailure::CapabilityClosed)
            .and_then(|response| {
                if self.inner.closed.load(Ordering::Acquire) {
                    Err(ForwardFailure::CapabilityClosed)
                } else {
                    Ok(response)
                }
            });
        self.settled = true;
        response
    }

    fn try_wait(&mut self) -> Option<Result<ServerMessage, ForwardFailure>> {
        let response = match self.receiver.as_ref()?.try_recv() {
            Ok(_) if self.inner.closed.load(Ordering::Acquire) => {
                Err(ForwardFailure::CapabilityClosed)
            }
            Ok(response) => Ok(response),
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => Err(ForwardFailure::CapabilityClosed),
        };
        self.receiver = None;
        self.settled = true;
        Some(response)
    }

    fn cancel(&mut self) {
        if self.settled || self.cancelled {
            return;
        }
        if self.cancellation_mode == CancellationMode::NotifyBroker {
            ForwardingClient {
                inner: Arc::clone(&self.inner),
            }
            .cancel(self.id);
        } else {
            self.receiver = None;
            self.settled = true;
        }
        self.cancelled = true;
    }

    fn current_policy(&self) -> Option<(bool, crate::config::SavedPortForwardLimit)> {
        let saved_mapping_limit = crate::config::SavedPortForwardLimit::new(
            self.inner.saved_mapping_limit.load(Ordering::Acquire),
        )?;
        Some((
            self.inner.active.load(Ordering::Acquire),
            saved_mapping_limit,
        ))
    }

    fn current_policy_or_closed(
        &self,
    ) -> (
        bool,
        crate::config::SavedPortForwardLimit,
        Result<(), ForwardFailure>,
    ) {
        let (effective, saved_mapping_limit) = self
            .current_policy()
            .unwrap_or((false, crate::config::SavedPortForwardLimit::DEFAULT));
        (
            effective,
            saved_mapping_limit,
            Err(ForwardFailure::CapabilityClosed),
        )
    }

    fn apply_policy_settlement(
        &self,
        settlement: (
            bool,
            crate::config::SavedPortForwardLimit,
            Result<(), ForwardFailure>,
        ),
    ) -> (
        bool,
        crate::config::SavedPortForwardLimit,
        Result<(), ForwardFailure>,
    ) {
        let (effective, reported_limit, result) = settlement;
        let saved_mapping_limit = if result.is_ok() {
            reported_limit
        } else if let Some((_, current)) = self.current_policy() {
            current
        } else {
            return self.current_policy_or_closed();
        };
        self.inner.active.store(effective, Ordering::Release);
        self.inner
            .saved_mapping_limit
            .store(saved_mapping_limit.get(), Ordering::Release);
        (effective, saved_mapping_limit, result)
    }
}

impl Drop for BrokerCallCore {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingResponseKind {
    Scalar,
    Localhost,
}

impl MappingResponseKind {
    fn decode(
        self,
        response: Result<ServerMessage, ForwardFailure>,
    ) -> Result<u16, ForwardFailure> {
        match self {
            Self::Scalar => forward_response(response),
            Self::Localhost => localhost_response(response),
        }
    }
}

pub(crate) struct MappingCall {
    response_kind: MappingResponseKind,
    core: BrokerCallCore,
}

impl MappingCall {
    #[cfg(test)]
    pub(crate) fn wait(mut self) -> Result<u16, ForwardFailure> {
        self.response_kind.decode(self.core.wait())
    }

    pub(crate) fn try_wait(&mut self) -> Option<Result<u16, ForwardFailure>> {
        self.core
            .try_wait()
            .map(|response| self.response_kind.decode(response))
    }

    pub(crate) fn cancel(&mut self) {
        self.core.cancel();
    }
}

fn forward_response(
    response: Result<ServerMessage, ForwardFailure>,
) -> Result<u16, ForwardFailure> {
    match response {
        Ok(ServerMessage::ForwardSettled { result, .. }) => result,
        Ok(ServerMessage::Cancelled { .. }) => Err(ForwardFailure::Cancelled),
        Ok(_) | Err(ForwardFailure::CapabilityClosed) => Err(ForwardFailure::CapabilityClosed),
        Err(error) => Err(error),
    }
}

fn localhost_response(
    response: Result<ServerMessage, ForwardFailure>,
) -> Result<u16, ForwardFailure> {
    match response {
        Ok(ServerMessage::ForwardLocalhostSettled { result, .. }) => result,
        Ok(ServerMessage::Cancelled { .. }) => Err(ForwardFailure::Cancelled),
        Ok(_) | Err(ForwardFailure::CapabilityClosed) => Err(ForwardFailure::CapabilityClosed),
        Err(error) => Err(error),
    }
}

pub(crate) struct PolicyCall {
    requested: bool,
    requested_saved_mapping_limit: crate::config::SavedPortForwardLimit,
    core: BrokerCallCore,
}

impl PolicyCall {
    fn wait(
        mut self,
    ) -> io::Result<(
        bool,
        crate::config::SavedPortForwardLimit,
        Result<(), ForwardFailure>,
    )> {
        let response = self.core.wait().ok();
        let settled =
            policy_response(self.requested, self.requested_saved_mapping_limit, response)?;
        Ok(self.core.apply_policy_settlement(settled))
    }

    pub(crate) fn try_wait(
        &mut self,
    ) -> Option<(
        bool,
        crate::config::SavedPortForwardLimit,
        Result<(), ForwardFailure>,
    )> {
        let response = match self.core.try_wait()? {
            Ok(response) => Some(response),
            Err(ForwardFailure::CapabilityClosed) => {
                return Some(self.core.current_policy_or_closed());
            }
            Err(error) => {
                let Some((effective, saved_mapping_limit)) = self.core.current_policy() else {
                    return Some(self.core.current_policy_or_closed());
                };
                return Some((effective, saved_mapping_limit, Err(error)));
            }
        };
        let settled = policy_response(self.requested, self.requested_saved_mapping_limit, response)
            .unwrap_or_else(|_| self.core.current_policy_or_closed());
        Some(self.core.apply_policy_settlement(settled))
    }

    pub(crate) fn cancel(&mut self) {
        self.core.cancel();
    }
}

fn policy_response(
    requested: bool,
    requested_saved_mapping_limit: crate::config::SavedPortForwardLimit,
    response: Option<ServerMessage>,
) -> io::Result<(
    bool,
    crate::config::SavedPortForwardLimit,
    Result<(), ForwardFailure>,
)> {
    let Some(ServerMessage::PolicyAcknowledged {
        requested: acknowledged,
        effective,
        saved_mapping_limit,
        result,
        ..
    }) = response
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forwarding broker policy acknowledgement rejected",
        ));
    };
    let saved_mapping_limit = crate::config::SavedPortForwardLimit::new(saved_mapping_limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "forwarding broker policy acknowledgement rejected",
            )
        })?;
    if acknowledged != requested
        || (result.is_ok() && saved_mapping_limit != requested_saved_mapping_limit)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "forwarding broker policy acknowledgement rejected",
        ));
    }
    Ok((effective, saved_mapping_limit, result))
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
enum MappingKind {
    Scalar {
        address: super::protocol::LoopbackAddress,
        remote_port: u16,
    },
    Localhost {
        remote_port: u16,
    },
}

impl MappingKind {
    const fn is_localhost(self) -> bool {
        matches!(self, Self::Localhost { .. })
    }

    fn request(self, mappings: &mut MappingRegistry, id: CorrelationId) -> MappingRequest {
        match self {
            Self::Scalar {
                address,
                remote_port,
            } => mappings.request_scalar(id, address, remote_port),
            Self::Localhost { remote_port } => mappings.request_localhost(id, remote_port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupOwner {
    BestEffort,
    Policy(CorrelationId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedJobKind {
    Mapping(MappingAttempt),
    Cleanup {
        owner: CleanupOwner,
        local_port: u16,
    },
}

struct PendingPolicyAcknowledgement {
    id: CorrelationId,
    requested: bool,
    change: SavedLimitChange,
    remaining_cleanups: usize,
    cleanup_failure: Option<ForwardFailure>,
    wait_for_idle: bool,
}

#[derive(Debug, Clone, Copy)]
struct QueuedJob {
    job: WorkerJob,
    kind: QueuedJobKind,
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
            Arc::new(super::worker::ProcessCommandRunner::default()),
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
        Self::start_with_runner_and_registry(
            stream,
            expected_child,
            authority,
            runner,
            timeout,
            MappingRegistry::default(),
        )
    }

    fn start_with_runner_and_registry(
        stream: UnixStream,
        expected_child: crate::platform::InheritedPeerIdentity,
        authority: ControlAuthority,
        runner: Arc<dyn CommandRunner>,
        timeout: Duration,
        mappings: MappingRegistry,
    ) -> io::Result<Self> {
        let control = stream.try_clone()?;
        let thread_control = stream.try_clone()?;
        let thread = std::thread::spawn(move || {
            run_broker(stream, expected_child, authority, runner, timeout, mappings);
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

fn finish_policy_acknowledgement(
    stream: &mut UnixStream,
    mappings: &mut MappingRegistry,
    pending: &mut Option<PendingPolicyAcknowledgement>,
    queue: &VecDeque<QueuedJob>,
    active: &Option<QueuedJob>,
) -> io::Result<()> {
    let ready = pending.as_ref().is_some_and(|pending| {
        pending.remaining_cleanups == 0
            && mappings.saved_limit_change_converged(&pending.change)
            && (!pending.wait_for_idle || (active.is_none() && queue.is_empty()))
    });
    if !ready {
        return Ok(());
    }
    let Some(pending) = pending.take() else {
        return Ok(());
    };
    let (saved_mapping_limit, result) = if let Some(failure) = pending.cleanup_failure {
        if !mappings.abort_saved_limit_change(&pending.change) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forwarding saved-limit change mismatch",
            ));
        }
        (mappings.saved_limit(), Err(failure))
    } else {
        if !mappings.commit_saved_limit(&pending.change) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forwarding saved-limit change mismatch",
            ));
        }
        (pending.change.requested_limit, Ok(()))
    };
    protocol::write_message(
        stream,
        &ServerMessage::PolicyAcknowledged {
            id: pending.id,
            requested: pending.requested,
            effective: pending.requested,
            saved_mapping_limit: saved_mapping_limit.get(),
            result,
        },
    )
}

fn run_broker(
    mut stream: UnixStream,
    expected_child: crate::platform::InheritedPeerIdentity,
    authority: ControlAuthority,
    runner: Arc<dyn CommandRunner>,
    timeout: Duration,
    mut mappings: MappingRegistry,
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
    let mut queue = VecDeque::<QueuedJob>::new();
    let mut active: Option<QueuedJob> = None;
    let mut pending_policy_ack = None;

    'broker: loop {
        while let Ok(result) = worker.try_recv() {
            let Some(completed) = active.take() else {
                break 'broker;
            };
            if completed.job.id != result.id || completed.job.operation != result.operation {
                break 'broker;
            }
            if result.result == ControlResult::MasterDied {
                let _ = mappings.master_died();
                break 'broker;
            }

            match completed.kind {
                QueuedJobKind::Mapping(attempt) => {
                    let Some(control_result) = mapping_control_result(result.result) else {
                        break 'broker;
                    };
                    let completion = mappings.complete(attempt, control_result);
                    if completion.invariant_error.is_some() {
                        break 'broker;
                    }
                    if let Some(next) = completion.attempt {
                        queue.push_front(mapping_job(next));
                    }
                    if let Some(cancelled) = completion.cancellation {
                        if let Some(policy_id) = completion.cancellation_policy {
                            let Some(pending) = pending_policy_ack.as_mut().filter(
                                |pending: &&mut PendingPolicyAcknowledgement| {
                                    pending.id == policy_id
                                },
                            ) else {
                                break 'broker;
                            };
                            let Some(remaining_cleanups) =
                                pending.remaining_cleanups.checked_add(1)
                            else {
                                break 'broker;
                            };
                            pending.remaining_cleanups = remaining_cleanups;
                            queue.push_front(policy_attempt_cleanup_job(cancelled, policy_id));
                        } else {
                            queue.push_front(cleanup_job(cancelled));
                        }
                    }
                    for settlement in completion.settlements {
                        if write_mapping_settlement(&mut stream, attempt.is_localhost(), settlement)
                            .is_err()
                        {
                            break 'broker;
                        }
                    }
                }
                QueuedJobKind::Cleanup { owner, local_port } => {
                    if let CleanupOwner::Policy(policy_id) = owner {
                        let Some(pending) = pending_policy_ack.as_mut().filter(
                            |pending: &&mut PendingPolicyAcknowledgement| {
                                pending.id == policy_id && pending.remaining_cleanups > 0
                            },
                        ) else {
                            break 'broker;
                        };
                        pending.remaining_cleanups -= 1;
                        let failure = cleanup_failure(result.result);
                        if failure.is_some() {
                            mappings.quarantine_uncertain(local_port);
                        }
                        if pending.cleanup_failure.is_none() {
                            pending.cleanup_failure = failure;
                        }
                    }
                }
            }
            if dispatch_next(&worker, &mut mappings, &mut queue, &mut active).is_err() {
                break 'broker;
            }
            if finish_policy_acknowledgement(
                &mut stream,
                &mut mappings,
                &mut pending_policy_ack,
                &queue,
                &active,
            )
            .is_err()
            {
                break 'broker;
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
                    ClientMessage::AssertPolicy {
                        id,
                        enabled,
                        saved_mapping_limit,
                    } if state != BrokerState::AwaitHello && pending_policy_ack.is_none() => {
                        let Some(saved_mapping_limit) =
                            crate::config::SavedPortForwardLimit::new(saved_mapping_limit)
                        else {
                            break 'broker;
                        };
                        let change = mappings.begin_saved_limit_change(saved_mapping_limit, id);
                        let mut remaining_cleanups = change.cancellations.len();
                        for cancellation in change.cancellations.iter().copied() {
                            queue.push_back(policy_cleanup_job(cancellation));
                        }
                        state = if enabled {
                            BrokerState::Active
                        } else {
                            BrokerState::Disabled
                        };
                        if !enabled {
                            let ready_cancellations = mappings.revoke_ready(id);
                            let Some(total_cleanups) =
                                remaining_cleanups.checked_add(ready_cancellations.len())
                            else {
                                break 'broker;
                            };
                            remaining_cleanups = total_cleanups;
                            for cancellation in ready_cancellations {
                                queue.push_back(policy_cleanup_job(cancellation));
                            }
                            for revoked in mappings.revoke_creating(id) {
                                if write_mapping_settlement(
                                    &mut stream,
                                    revoked.localhost,
                                    revoked.settlement,
                                )
                                .is_err()
                                {
                                    break 'broker;
                                }
                            }
                        }
                        pending_policy_ack = Some(PendingPolicyAcknowledgement {
                            id,
                            requested: enabled,
                            change,
                            remaining_cleanups,
                            cleanup_failure: None,
                            wait_for_idle: !enabled,
                        });
                        if dispatch_next(&worker, &mut mappings, &mut queue, &mut active).is_err() {
                            break 'broker;
                        }
                        if finish_policy_acknowledgement(
                            &mut stream,
                            &mut mappings,
                            &mut pending_policy_ack,
                            &queue,
                            &active,
                        )
                        .is_err()
                        {
                            break 'broker;
                        }
                    }
                    ClientMessage::Forward { id, spec }
                        if matches!(state, BrokerState::Disabled | BrokerState::Active)
                            && spec.is_valid() =>
                    {
                        if handle_mapping_dispatch(
                            &worker,
                            &mut stream,
                            &mut mappings,
                            &mut queue,
                            &mut active,
                            state,
                            id,
                            MappingKind::Scalar {
                                address: spec.remote_address,
                                remote_port: spec.remote_port,
                            },
                        )
                        .is_err()
                        {
                            break 'broker;
                        }
                    }
                    ClientMessage::ForwardLocalhost { id, remote_port }
                        if matches!(state, BrokerState::Disabled | BrokerState::Active)
                            && remote_port != 0 =>
                    {
                        if handle_mapping_dispatch(
                            &worker,
                            &mut stream,
                            &mut mappings,
                            &mut queue,
                            &mut active,
                            state,
                            id,
                            MappingKind::Localhost { remote_port },
                        )
                        .is_err()
                        {
                            break 'broker;
                        }
                    }
                    ClientMessage::Cancel { id } if state != BrokerState::AwaitHello => {
                        match mappings.cancel_waiter(id) {
                            WaiterCancellation::NotFound => {}
                            WaiterCancellation::Removed => {
                                let _ = protocol::write_message(
                                    &mut stream,
                                    &ServerMessage::Cancelled { id },
                                );
                            }
                            WaiterCancellation::AbandonedBeforeStart(attempt) => {
                                if let Some(position) = queue.iter().position(|queued| {
                                    queued.kind == QueuedJobKind::Mapping(attempt)
                                }) {
                                    queue.remove(position);
                                }
                                let _ = protocol::write_message(
                                    &mut stream,
                                    &ServerMessage::Cancelled { id },
                                );
                            }
                        }
                    }
                    _ => break 'broker,
                }
            }
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => break 'broker,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }

    let _ = mappings.master_died();
}

fn mapping_job(attempt: MappingAttempt) -> QueuedJob {
    QueuedJob {
        job: WorkerJob {
            id: attempt.controller_id(),
            operation: attempt.operation(),
        },
        kind: QueuedJobKind::Mapping(attempt),
    }
}

fn cleanup_job(attempt: MappingAttempt) -> QueuedJob {
    QueuedJob {
        job: WorkerJob {
            id: attempt.controller_id(),
            operation: attempt.cancellation(),
        },
        kind: QueuedJobKind::Cleanup {
            owner: CleanupOwner::BestEffort,
            local_port: attempt.local_port(),
        },
    }
}

fn policy_attempt_cleanup_job(attempt: MappingAttempt, policy_id: CorrelationId) -> QueuedJob {
    QueuedJob {
        job: WorkerJob {
            id: policy_id,
            operation: attempt.cancellation(),
        },
        kind: QueuedJobKind::Cleanup {
            owner: CleanupOwner::Policy(policy_id),
            local_port: attempt.local_port(),
        },
    }
}

fn replacement_cleanup_job(cancellation: MappingCancellation) -> QueuedJob {
    QueuedJob {
        job: WorkerJob {
            id: cancellation.controller_id(),
            operation: cancellation.operation(),
        },
        kind: QueuedJobKind::Cleanup {
            owner: CleanupOwner::BestEffort,
            local_port: cancellation.local_port(),
        },
    }
}

fn policy_cleanup_job(cancellation: MappingCancellation) -> QueuedJob {
    QueuedJob {
        job: WorkerJob {
            id: cancellation.controller_id(),
            operation: cancellation.operation(),
        },
        kind: QueuedJobKind::Cleanup {
            owner: CleanupOwner::Policy(cancellation.controller_id()),
            local_port: cancellation.local_port(),
        },
    }
}

fn cleanup_failure(result: ControlResult) -> Option<ForwardFailure> {
    match result {
        ControlResult::Succeeded | ControlResult::PairCancellationSucceeded => None,
        ControlResult::TimedOut | ControlResult::PairFirstTimedOut => {
            Some(ForwardFailure::CommandTimedOut)
        }
        ControlResult::BindFailed
        | ControlResult::Rejected
        | ControlResult::PairSucceeded
        | ControlResult::PairFirstBindFailed
        | ControlResult::PairFirstFailed
        | ControlResult::PairSecondFailed
        | ControlResult::PairCancellationFailed => Some(ForwardFailure::CommandRejected),
        ControlResult::MasterDied => Some(ForwardFailure::CapabilityClosed),
    }
}

fn mapping_control_result(result: ControlResult) -> Option<MappingControlResult> {
    match result {
        ControlResult::Succeeded => Some(MappingControlResult::Succeeded),
        ControlResult::BindFailed => Some(MappingControlResult::BindFailed),
        ControlResult::Rejected => Some(MappingControlResult::Rejected),
        ControlResult::TimedOut => Some(MappingControlResult::TimedOut),
        ControlResult::PairSucceeded => Some(MappingControlResult::PairSucceeded),
        ControlResult::PairFirstBindFailed => Some(MappingControlResult::PairFirstBindFailed),
        ControlResult::PairFirstFailed => Some(MappingControlResult::PairFirstFailed),
        ControlResult::PairFirstTimedOut => Some(MappingControlResult::PairFirstTimedOut),
        ControlResult::PairSecondFailed => Some(MappingControlResult::PairSecondFailed),
        ControlResult::PairCancellationSucceeded
        | ControlResult::PairCancellationFailed
        | ControlResult::MasterDied => None,
    }
}

fn handle_mapping_dispatch(
    worker: &ControlWorker,
    stream: &mut UnixStream,
    mappings: &mut MappingRegistry,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
    state: BrokerState,
    id: CorrelationId,
    kind: MappingKind,
) -> io::Result<()> {
    let localhost = kind.is_localhost();
    if state == BrokerState::Disabled {
        return write_mapping_settlement(
            stream,
            localhost,
            MappingSettlement::failed(id, ForwardFailure::Disabled),
        );
    }
    let request = kind.request(mappings, id);
    handle_mapping_request(worker, stream, mappings, queue, active, localhost, request)
}

fn handle_mapping_request(
    worker: &ControlWorker,
    stream: &mut UnixStream,
    mappings: &mut MappingRegistry,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
    localhost: bool,
    request: MappingRequest,
) -> io::Result<()> {
    match request {
        MappingRequest::Ready(settlement) | MappingRequest::Failed(settlement) => {
            write_mapping_settlement(stream, localhost, settlement)
        }
        MappingRequest::Pending { attempt } => {
            if let Some(attempt) = attempt {
                queue.push_back(mapping_job(attempt));
                dispatch_next(worker, mappings, queue, active)?;
            }
            Ok(())
        }
        MappingRequest::Replacing {
            attempt,
            cancellation,
        } => {
            queue.push_back(replacement_cleanup_job(cancellation));
            queue.push_back(mapping_job(attempt));
            dispatch_next(worker, mappings, queue, active)
        }
    }
}

fn write_mapping_settlement(
    stream: &mut UnixStream,
    localhost: bool,
    settlement: MappingSettlement,
) -> io::Result<()> {
    let message = if localhost {
        ServerMessage::ForwardLocalhostSettled {
            id: settlement.id,
            result: settlement.result,
        }
    } else {
        ServerMessage::ForwardSettled {
            id: settlement.id,
            result: settlement.result,
        }
    };
    protocol::write_message(stream, &message)
}

fn dispatch_next(
    worker: &ControlWorker,
    mappings: &mut MappingRegistry,
    queue: &mut VecDeque<QueuedJob>,
    active: &mut Option<QueuedJob>,
) -> io::Result<()> {
    while active.is_none() {
        let Some(next) = queue.pop_front() else {
            break;
        };
        if let QueuedJobKind::Mapping(attempt) = next.kind {
            if !mappings.start(attempt) {
                continue;
            }
        }
        worker.submit(next.job)?;
        *active = Some(next);
    }
    Ok(())
}

#[cfg(test)]
struct HarnessRunner {
    operations: Mutex<Vec<String>>,
    block_first: AtomicBool,
    started: Option<mpsc::SyncSender<()>>,
    release: Option<Mutex<mpsc::Receiver<()>>>,
}

#[cfg(test)]
impl CommandRunner for HarnessRunner {
    fn run(
        &self,
        invocation: &super::worker::ControlInvocation,
        _timeout: Duration,
    ) -> ControlResult {
        let operation = invocation
            .args
            .windows(2)
            .find_map(|args| (args[0] == "-O").then(|| args[1].clone()))
            .expect("control operation");
        self.operations
            .lock()
            .expect("harness operations")
            .push(operation);
        if self.block_first.swap(false, Ordering::AcqRel) {
            if let Some(started) = &self.started {
                started.send(()).expect("report blocked command");
            }
            if let Some(release) = &self.release {
                release
                    .lock()
                    .expect("release receiver")
                    .recv()
                    .expect("release blocked command");
            }
        }
        ControlResult::Succeeded
    }

    fn cancel(&self) {}
}

#[cfg(test)]
pub(crate) struct ForwardingBrokerTestHarness {
    broker: Option<BrokerServer>,
    controller: Arc<super::controller::NumericForwardingController>,
    runner: Arc<HarnessRunner>,
    started: Option<mpsc::Receiver<()>>,
    release: Option<mpsc::SyncSender<()>>,
}

#[cfg(test)]
impl ForwardingBrokerTestHarness {
    pub(crate) fn blocked(saved_mapping_limit: crate::config::SavedPortForwardLimit) -> Self {
        let (started_sender, started) = mpsc::sync_channel(1);
        let (release, release_receiver) = mpsc::sync_channel(1);
        Self::start(
            saved_mapping_limit,
            HarnessRunner {
                operations: Mutex::new(Vec::new()),
                block_first: AtomicBool::new(true),
                started: Some(started_sender),
                release: Some(Mutex::new(release_receiver)),
            },
            Some(started),
            Some(release),
        )
    }

    pub(crate) fn succeeding(saved_mapping_limit: crate::config::SavedPortForwardLimit) -> Self {
        Self::start(
            saved_mapping_limit,
            HarnessRunner {
                operations: Mutex::new(Vec::new()),
                block_first: AtomicBool::new(false),
                started: None,
                release: None,
            },
            None,
            None,
        )
    }

    fn start(
        saved_mapping_limit: crate::config::SavedPortForwardLimit,
        runner: HarnessRunner,
        started: Option<mpsc::Receiver<()>>,
        release: Option<mpsc::SyncSender<()>>,
    ) -> Self {
        let runner = Arc::new(runner);
        let (parent, child) = UnixStream::pair().expect("broker harness pair");
        let broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            ControlAuthority::new(
                "test-target".to_owned(),
                std::path::PathBuf::from("/test/control"),
            ),
            runner.clone(),
            Duration::from_secs(10),
        )
        .expect("broker harness server");
        let client = ForwardingClient::from_stream(
            child,
            true,
            saved_mapping_limit,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("broker harness client");
        Self {
            broker: Some(broker),
            controller: Arc::new(super::controller::NumericForwardingController::new(client)),
            runner,
            started,
            release,
        }
    }

    pub(crate) fn controller(&self) -> Arc<dyn crate::external_open::ForwardingController> {
        self.controller.clone()
    }

    pub(crate) fn wait_until_blocked(&self) {
        self.started
            .as_ref()
            .expect("blocked harness")
            .recv()
            .expect("blocked command started");
    }

    pub(crate) fn release_blocked(&mut self) {
        if let Some(release) = self.release.take() {
            release.send(()).expect("release blocked command");
        }
    }

    pub(crate) fn operations(&self) -> Vec<String> {
        self.runner
            .operations
            .lock()
            .expect("harness operations")
            .clone()
    }

    pub(crate) fn operation_count(&self, expected: &str) -> usize {
        self.runner
            .operations
            .lock()
            .expect("harness operations")
            .iter()
            .filter(|operation| operation.as_str() == expected)
            .count()
    }

    pub(crate) fn total_operations(&self) -> usize {
        self.runner
            .operations
            .lock()
            .expect("harness operations")
            .len()
    }
}

#[cfg(test)]
impl Drop for ForwardingBrokerTestHarness {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.broker.take();
    }
}

#[cfg(test)]
mod tests {
    fn saved_limit(value: u8) -> crate::config::SavedPortForwardLimit {
        crate::config::SavedPortForwardLimit::new(value).expect("valid saved mapping limit")
    }

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

    struct GateRunner {
        first: AtomicBool,
        started: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    struct SteppedCommand {
        invocation: ControlInvocation,
        result: mpsc::SyncSender<ControlResult>,
    }

    impl SteppedCommand {
        fn operation(&self) -> &str {
            self.invocation
                .args
                .windows(2)
                .find_map(|args| (args[0] == "-O").then_some(args[1].as_str()))
                .expect("control operation")
        }

        fn forward_value(&self) -> &str {
            self.invocation
                .args
                .windows(2)
                .find_map(|args| (args[0] == "-L").then_some(args[1].as_str()))
                .expect("forward value")
        }

        fn settle(self, result: ControlResult) {
            self.result.send(result).expect("settle stepped command");
        }
    }

    struct SteppedRunner {
        commands: mpsc::Sender<SteppedCommand>,
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

        fn cancel(&self) {}
    }

    impl CommandRunner for GateRunner {
        fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            if self.first.swap(false, Ordering::AcqRel) {
                let _ = self.started.send(());
                let _ = self.release.lock().expect("release gate").recv();
            }
            ControlResult::Succeeded
        }

        fn cancel(&self) {}
    }

    impl CommandRunner for CountingRunner {
        fn run(&self, _invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            ControlResult::Succeeded
        }

        fn cancel(&self) {}
    }

    impl CommandRunner for SteppedRunner {
        fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
            let (result, receiver) = mpsc::sync_channel(1);
            if self
                .commands
                .send(SteppedCommand {
                    invocation: invocation.clone(),
                    result,
                })
                .is_err()
            {
                return ControlResult::Rejected;
            }
            receiver.recv().unwrap_or(ControlResult::Rejected)
        }

        fn cancel(&self) {}
    }

    fn stepped_broker(
        saved_mapping_limit: crate::config::SavedPortForwardLimit,
    ) -> (
        BrokerServer,
        ForwardingClient,
        mpsc::Receiver<SteppedCommand>,
    ) {
        let (commands, receiver) = mpsc::channel();
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            Arc::new(SteppedRunner { commands }),
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream(
            child,
            true,
            saved_mapping_limit,
            crate::platform::InheritedPeerIdentity::current_process(),
        )
        .expect("broker client");
        (broker, client, receiver)
    }

    fn next_command(receiver: &mpsc::Receiver<SteppedCommand>) -> SteppedCommand {
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("next stepped command")
    }

    fn wait_for_policy(
        call: &mut PolicyCall,
    ) -> (
        bool,
        crate::config::SavedPortForwardLimit,
        Result<(), ForwardFailure>,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(settlement) = call.try_wait() {
                return settlement;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "policy call timed out"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_for_mapping(call: &mut MappingCall) -> Result<u16, ForwardFailure> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(settlement) = call.try_wait() {
                return settlement;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "mapping call timed out"
            );
            std::thread::sleep(Duration::from_millis(1));
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

    fn read_broker_client_message(stream: &mut UnixStream) -> ClientMessage {
        let payload = protocol::read_payload(stream).expect("client frame");
        protocol::decode_message(&payload).expect("client message")
    }

    fn acknowledge_manual_handshake(stream: &mut UnixStream) {
        let ClientMessage::Hello { id, version } = read_broker_client_message(stream) else {
            panic!("hello");
        };
        protocol::write_message(stream, &ServerMessage::HelloAcknowledged { id, version })
            .expect("hello acknowledgement");
        let ClientMessage::AssertPolicy {
            id,
            enabled,
            saved_mapping_limit,
        } = read_broker_client_message(stream)
        else {
            panic!("initial policy");
        };
        protocol::write_message(
            stream,
            &ServerMessage::PolicyAcknowledged {
                id,
                requested: enabled,
                effective: enabled,
                saved_mapping_limit,
                result: Ok(()),
            },
        )
        .expect("initial policy acknowledgement");
    }

    fn authority() -> ControlAuthority {
        ControlAuthority::new(
            "secret-target".to_string(),
            PathBuf::from("/secret/control"),
        )
    }

    fn settle_forward(client: &ForwardingClient, spec: ForwardSpec) -> Result<u16, ForwardFailure> {
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
        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_disconnected_mismatched_and_duplicate_policy_acks_retain_validated_limit() {
        enum ManualOutcome {
            Disconnect,
            Mismatch,
            InvalidLimit(u8),
            Duplicate,
            ErrorWithRequestedLimit,
        }

        for (outcome, expected_effective, expected_failure) in [
            (
                ManualOutcome::Disconnect,
                false,
                ForwardFailure::CapabilityClosed,
            ),
            (
                ManualOutcome::Mismatch,
                true,
                ForwardFailure::CapabilityClosed,
            ),
            (
                ManualOutcome::InvalidLimit(0),
                true,
                ForwardFailure::CapabilityClosed,
            ),
            (
                ManualOutcome::InvalidLimit(65),
                true,
                ForwardFailure::CapabilityClosed,
            ),
            (
                ManualOutcome::Duplicate,
                false,
                ForwardFailure::CapabilityClosed,
            ),
            (
                ManualOutcome::ErrorWithRequestedLimit,
                true,
                ForwardFailure::CommandRejected,
            ),
        ] {
            let (mut parent, child) = UnixStream::pair().expect("broker pair");
            let server = std::thread::spawn(move || {
                acknowledge_manual_handshake(&mut parent);
                let ClientMessage::AssertPolicy {
                    id,
                    enabled,
                    saved_mapping_limit,
                } = read_broker_client_message(&mut parent)
                else {
                    panic!("live policy");
                };
                match outcome {
                    ManualOutcome::Disconnect => {}
                    ManualOutcome::Mismatch => {
                        protocol::write_message(
                            &mut parent,
                            &ServerMessage::PolicyAcknowledged {
                                id,
                                requested: enabled,
                                effective: enabled,
                                saved_mapping_limit: saved_mapping_limit - 1,
                                result: Ok(()),
                            },
                        )
                        .expect("mismatched acknowledgement");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ManualOutcome::InvalidLimit(saved_mapping_limit) => {
                        protocol::write_message(
                            &mut parent,
                            &ServerMessage::PolicyAcknowledged {
                                id,
                                requested: enabled,
                                effective: enabled,
                                saved_mapping_limit,
                                result: Ok(()),
                            },
                        )
                        .expect("invalid-limit acknowledgement");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ManualOutcome::Duplicate => {
                        let acknowledgement = ServerMessage::PolicyAcknowledged {
                            id,
                            requested: enabled,
                            effective: enabled,
                            saved_mapping_limit,
                            result: Ok(()),
                        };
                        protocol::write_message(&mut parent, &acknowledgement)
                            .expect("first acknowledgement");
                        protocol::write_message(&mut parent, &acknowledgement)
                            .expect("duplicate acknowledgement");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ManualOutcome::ErrorWithRequestedLimit => {
                        protocol::write_message(
                            &mut parent,
                            &ServerMessage::PolicyAcknowledged {
                                id,
                                requested: enabled,
                                effective: enabled,
                                saved_mapping_limit,
                                result: Err(ForwardFailure::CommandRejected),
                            },
                        )
                        .expect("error acknowledgement");
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            });
            let client =
                ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
            let mut call = client
                .begin_assert_policy(true, saved_limit(64))
                .expect("live policy call");
            let settlement = loop {
                if let Some(settlement) = call.try_wait() {
                    break settlement;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(
                settlement,
                (
                    expected_effective,
                    crate::config::SavedPortForwardLimit::DEFAULT,
                    Err(expected_failure),
                )
            );
            server.join().expect("manual broker");
        }
    }

    #[test]
    fn acknowledged_live_limits_apply_immediately_with_ordered_best_effort_replacement() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
            ControlResult::Succeeded,
            ControlResult::TimedOut,
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

        assert_eq!(settle_forward(&client, spec_for_port(8_000)), Ok(8_000));
        assert_eq!(settle_forward(&client, spec_for_port(8_001)), Ok(8_001));
        assert_eq!(settle_forward(&client, spec_for_port(8_000)), Ok(8_000));
        client
            .assert_policy_with_limit(true, saved_limit(1))
            .expect("decrease acknowledged");
        assert_eq!(settle_forward(&client, spec_for_port(8_002)), Ok(8_002));
        client
            .assert_policy_with_limit(true, saved_limit(2))
            .expect("increase acknowledged");
        assert_eq!(settle_forward(&client, spec_for_port(8_003)), Ok(8_003));

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "cancel", "forward", "forward"]
        );
    }

    #[test]
    fn failed_limit_cleanup_is_not_acknowledged_and_retains_prior_limit() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
            ControlResult::Rejected,
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
        client
            .assert_policy_with_limit(true, saved_limit(2))
            .expect("initial limit");
        assert_eq!(settle_forward(&client, spec_for_port(8_000)), Ok(8_000));
        assert_eq!(settle_forward(&client, spec_for_port(8_001)), Ok(8_001));

        assert_eq!(
            client
                .begin_assert_policy(true, saved_limit(1))
                .expect("decrease call")
                .wait()
                .expect("typed policy acknowledgement"),
            (true, saved_limit(2), Err(ForwardFailure::CommandRejected))
        );
        assert_eq!(settle_forward(&client, spec_for_port(8_002)), Ok(8_002));
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "forward"]
        );
    }

    #[test]
    fn timed_out_limit_cleanup_retains_acknowledged_limit() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
            ControlResult::TimedOut,
            ControlResult::Succeeded,
        ]));
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        client
            .assert_policy_with_limit(true, saved_limit(2))
            .expect("initial limit");
        assert_eq!(settle_forward(&client, spec_for_port(8_000)), Ok(8_000));
        assert_eq!(settle_forward(&client, spec_for_port(8_001)), Ok(8_001));
        assert_eq!(
            client
                .begin_assert_policy(true, saved_limit(1))
                .expect("decrease call")
                .wait()
                .expect("typed acknowledgement"),
            (true, saved_limit(2), Err(ForwardFailure::CommandTimedOut))
        );
        assert_eq!(settle_forward(&client, spec_for_port(8_002)), Ok(8_002));
    }

    #[test]
    fn localhost_lru_replacement_cancels_ipv4_then_ipv6_despite_first_failure() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Succeeded,
            ControlResult::Rejected,
            ControlResult::TimedOut,
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
        client
            .assert_policy_with_limit(true, saved_limit(1))
            .expect("single saved mapping");

        assert_eq!(
            client.begin_localhost(8_080).expect("pair").wait(),
            Ok(8_080)
        );
        assert_eq!(settle_forward(&client, spec_for_port(8_081)), Ok(8_081));
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "cancel", "forward"]
        );
    }

    #[test]
    fn socket_broker_enforces_exact_forward_and_waiter_caps_without_slot_leaks() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(GateRunner {
            first: AtomicBool::new(true),
            started: started_tx,
            release: Mutex::new(release_rx),
        });
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
        client
            .assert_policy_with_limit(true, saved_limit(64))
            .expect("maximum saved limit");
        let mut active = vec![client.begin_forward(spec_for_port(8_000)).expect("first")];
        started_rx.recv().expect("first command started");
        active.extend((1..32).map(|offset| {
            client
                .begin_forward(spec_for_port(8_000 + offset))
                .expect("within request cap")
        }));
        assert_eq!(
            client
                .begin_forward(spec_for_port(9_000))
                .expect("typed request rejection")
                .wait(),
            Err(ForwardFailure::TooManyRequests)
        );
        release_tx.send(()).expect("release worker");
        for call in active {
            assert!(call.wait().is_ok());
        }

        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(GateRunner {
            first: AtomicBool::new(true),
            started: started_tx,
            release: Mutex::new(release_rx),
        });
        let (parent, child) = UnixStream::pair().expect("waiter broker pair");
        let _waiter_broker = BrokerServer::start_with_runner(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner,
            Duration::from_secs(10),
        )
        .expect("waiter broker");
        let waiter_client =
            ForwardingClient::from_stream_for_test(child, true).expect("waiter client");
        let mut waiters = vec![waiter_client.begin_forward(spec()).expect("owner")];
        started_rx.recv().expect("mapping command started");
        waiters.extend((1..8).map(|_| waiter_client.begin_forward(spec()).expect("waiter")));
        assert_eq!(
            waiter_client
                .begin_forward(spec())
                .expect("typed waiter rejection")
                .wait(),
            Err(ForwardFailure::TooManyWaiters)
        );
        release_tx.send(()).expect("release waiter worker");
        for waiter in waiters {
            assert_eq!(waiter.wait(), Ok(8_080));
        }
    }

    #[test]
    fn mixed_ready_and_creating_decrease_converges_before_one_acknowledgement() {
        let (_broker, client, commands) = stepped_broker(saved_limit(3));

        let old_ready = client
            .begin_forward(spec_for_port(8_000))
            .expect("old ready mapping");
        next_command(&commands).settle(ControlResult::Succeeded);
        assert_eq!(old_ready.wait(), Ok(8_000));

        let first_creating = client
            .begin_forward(spec_for_port(8_001))
            .expect("first creating mapping");
        let first_forward = next_command(&commands);
        assert_eq!(first_forward.operation(), "forward");
        assert!(first_forward.forward_value().contains(":8001:"));
        let second_creating = client
            .begin_forward(spec_for_port(8_002))
            .expect("queued creating mapping");
        let mut policy = client
            .begin_assert_policy(true, saved_limit(1))
            .expect("decrease policy");
        let mut distinct = client
            .begin_forward(spec_for_port(8_003))
            .expect("typed distinct rejection");
        let coalesced_second = client
            .begin_forward(spec_for_port(8_002))
            .expect("coalesced creating request");
        assert_eq!(
            wait_for_mapping(&mut distinct),
            Err(ForwardFailure::TooManyRequests)
        );
        assert_eq!(policy.try_wait(), None);

        first_forward.settle(ControlResult::Succeeded);
        let completed_cleanup = next_command(&commands);
        assert_eq!(completed_cleanup.operation(), "cancel");
        assert!(completed_cleanup.forward_value().contains(":8001:"));
        assert_eq!(
            first_creating.wait(),
            Err(ForwardFailure::CapacityExhausted)
        );
        assert_eq!(policy.try_wait(), None);
        completed_cleanup.settle(ControlResult::Succeeded);

        let second_forward = next_command(&commands);
        assert_eq!(second_forward.operation(), "forward");
        assert!(second_forward.forward_value().contains(":8002:"));
        assert_eq!(policy.try_wait(), None);
        second_forward.settle(ControlResult::Succeeded);
        assert_eq!(second_creating.wait(), Ok(8_002));
        assert_eq!(coalesced_second.wait(), Ok(8_002));

        let old_ready_cleanup = next_command(&commands);
        assert_eq!(old_ready_cleanup.operation(), "cancel");
        assert!(old_ready_cleanup.forward_value().contains(":8000:"));
        assert_eq!(policy.try_wait(), None);
        old_ready_cleanup.settle(ControlResult::Succeeded);

        assert_eq!(wait_for_policy(&mut policy), (true, saved_limit(1), Ok(())));
        assert_eq!(settle_forward(&client, spec_for_port(8_002)), Ok(8_002));
        let mut increase = client
            .begin_assert_policy(true, saved_limit(2))
            .expect("subsequent policy call");
        assert_eq!(
            wait_for_policy(&mut increase),
            (true, saved_limit(2), Ok(()))
        );
        assert!(commands.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn mixed_decrease_cleanup_failure_retains_old_limit_after_exact_settlement() {
        let (_broker, client, commands) = stepped_broker(saved_limit(3));

        let old_ready = client
            .begin_forward(spec_for_port(8_000))
            .expect("old ready mapping");
        next_command(&commands).settle(ControlResult::Succeeded);
        assert_eq!(old_ready.wait(), Ok(8_000));

        let first_creating = client
            .begin_forward(spec_for_port(8_001))
            .expect("first creating mapping");
        let first_forward = next_command(&commands);
        let second_creating = client
            .begin_forward(spec_for_port(8_002))
            .expect("queued creating mapping");
        let mut policy = client
            .begin_assert_policy(true, saved_limit(1))
            .expect("decrease policy");
        let mut distinct = client
            .begin_forward(spec_for_port(8_003))
            .expect("typed distinct rejection");
        assert_eq!(
            wait_for_mapping(&mut distinct),
            Err(ForwardFailure::TooManyRequests)
        );

        first_forward.settle(ControlResult::Succeeded);
        let completed_cleanup = next_command(&commands);
        assert_eq!(completed_cleanup.operation(), "cancel");
        assert!(completed_cleanup.forward_value().contains(":8001:"));
        assert_eq!(
            first_creating.wait(),
            Err(ForwardFailure::CapacityExhausted)
        );
        completed_cleanup.settle(ControlResult::Rejected);
        assert_eq!(policy.try_wait(), None);

        next_command(&commands).settle(ControlResult::Succeeded);
        assert_eq!(second_creating.wait(), Ok(8_002));
        let old_ready_cleanup = next_command(&commands);
        assert_eq!(old_ready_cleanup.operation(), "cancel");
        assert!(old_ready_cleanup.forward_value().contains(":8000:"));
        old_ready_cleanup.settle(ControlResult::Succeeded);

        assert_eq!(
            wait_for_policy(&mut policy),
            (true, saved_limit(3), Err(ForwardFailure::CommandRejected),)
        );
        let new_mapping = client
            .begin_forward(spec_for_port(8_003))
            .expect("old limit admits distinct work");
        next_command(&commands).settle(ControlResult::Succeeded);
        assert_eq!(new_mapping.wait(), Ok(8_003));
        assert!(commands.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn pending_decrease_allows_retained_ready_reuse_without_new_work() {
        let (_broker, client, commands) = stepped_broker(saved_limit(3));

        for port in [8_000, 8_001] {
            let ready = client
                .begin_forward(spec_for_port(port))
                .expect("ready mapping");
            next_command(&commands).settle(ControlResult::Succeeded);
            assert_eq!(ready.wait(), Ok(port));
        }
        assert_eq!(settle_forward(&client, spec_for_port(8_001)), Ok(8_001));

        let creating = client
            .begin_forward(spec_for_port(8_002))
            .expect("creating mapping");
        let creating_command = next_command(&commands);
        let mut policy = client
            .begin_assert_policy(true, saved_limit(2))
            .expect("decrease policy");
        let retained_reuse = client
            .begin_forward(spec_for_port(8_001))
            .expect("retained ready reuse");
        assert_eq!(retained_reuse.wait(), Ok(8_001));
        assert_eq!(policy.try_wait(), None);

        creating_command.settle(ControlResult::Succeeded);
        assert_eq!(creating.wait(), Ok(8_002));
        let old_ready_cleanup = next_command(&commands);
        assert_eq!(old_ready_cleanup.operation(), "cancel");
        assert!(old_ready_cleanup.forward_value().contains(":8000:"));
        assert_eq!(policy.try_wait(), None);
        old_ready_cleanup.settle(ControlResult::Succeeded);

        assert_eq!(wait_for_policy(&mut policy), (true, saved_limit(2), Ok(())));
        assert_eq!(settle_forward(&client, spec_for_port(8_001)), Ok(8_001));
        assert_eq!(settle_forward(&client, spec_for_port(8_002)), Ok(8_002));
        assert!(commands.recv_timeout(Duration::from_millis(50)).is_err());
    }

    #[test]
    fn over_limit_settlement_reports_decrease_owned_self_cleanup_failure() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [
                ControlResult::Succeeded,
                ControlResult::Rejected,
                ControlResult::Succeeded,
                ControlResult::Succeeded,
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
        client
            .assert_policy_with_limit(true, saved_limit(3))
            .expect("initial limit");
        let first = client.begin_forward(spec_for_port(8_000)).expect("first");
        let second = client.begin_forward(spec_for_port(8_001)).expect("second");
        let third = client.begin_forward(spec_for_port(8_002)).expect("third");
        let mut policy = client
            .begin_assert_policy(true, saved_limit(2))
            .expect("all-creating decrease");

        assert_eq!(first.wait(), Err(ForwardFailure::CapacityExhausted));
        assert_eq!(second.wait(), Ok(8_001));
        assert_eq!(third.wait(), Ok(8_002));
        assert_eq!(
            wait_for_policy(&mut policy),
            (true, saved_limit(3), Err(ForwardFailure::CommandRejected),)
        );
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "cancel", "forward", "forward"]
        );
    }

    #[test]
    fn concurrent_scalar_requests_coalesce_and_ready_reuse_returns_one_local_port() {
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

        let first = client.begin_forward(spec()).expect("first forward");
        let repeated = client.begin_forward(spec()).expect("repeated destination");

        assert_eq!(repeated.wait(), Ok(8080));
        assert_eq!(first.wait(), Ok(8080));
        assert_eq!(
            client.begin_forward(spec()).expect("ready reuse").wait(),
            Ok(8080)
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn coalesced_scalar_failure_reaches_all_waiters_and_later_click_retries() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [ControlResult::Rejected, ControlResult::Succeeded],
            Duration::from_millis(50),
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
        let first = client.begin_forward(spec()).expect("first");
        let second = client.begin_forward(spec()).expect("second");

        assert_eq!(first.wait(), Err(ForwardFailure::CommandRejected));
        assert_eq!(second.wait(), Err(ForwardFailure::CommandRejected));
        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
        );
    }

    #[test]
    fn scalar_waiter_cancellation_keeps_other_and_final_started_attempts_coherent() {
        let runner = Arc::new(CountingRunner {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(60),
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
        let first = client.begin_forward(spec()).expect("first");
        let second = client.begin_forward(spec()).expect("second");
        drop(first);
        assert_eq!(second.wait(), Ok(8080));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);

        let final_waiter = client
            .begin_forward(spec_for_port(8081))
            .expect("final waiter");
        while runner.calls.load(Ordering::SeqCst) < 2 {
            std::thread::yield_now();
        }
        drop(final_waiter);
        std::thread::sleep(Duration::from_millis(90));
        assert_eq!(settle_forward(&client, spec_for_port(8081)), Ok(8081));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn disabling_a_ready_scalar_mapping_cancels_it_before_reenable_creates_fresh() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
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

        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        client.assert_policy(false).expect("disable policy");
        client.assert_policy(true).expect("re-enable policy");
        assert_eq!(settle_forward(&client, spec()), Ok(8080));

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "cancel", "forward"]
        );
    }

    #[test]
    fn failed_disable_cleanup_quarantines_the_owned_port_across_reenable() {
        let runner = Arc::new(RecordingRunner::new([
            ControlResult::Succeeded,
            ControlResult::Rejected,
            ControlResult::Succeeded,
        ]));
        let (mappings, candidate_calls) = MappingRegistry::for_broker_test([43_123]);
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner_and_registry(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
            mappings,
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        let mut disable = client
            .begin_assert_policy(false, saved_limit(12))
            .expect("begin disable");
        assert_eq!(
            wait_for_policy(&mut disable),
            (false, saved_limit(12), Err(ForwardFailure::CommandRejected))
        );
        client.assert_policy(true).expect("re-enable policy");
        assert_eq!(settle_forward(&client, spec()), Ok(43_123));

        assert_eq!(candidate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "cancel", "forward"]
        );
    }

    #[test]
    fn fresh_reattachment_remaps_foreign_collision_and_cleans_only_owned_listeners() {
        struct OwnedListenerRunner {
            occupied: Mutex<BTreeMap<u16, String>>,
            operations: Mutex<Vec<(String, String, u16)>>,
        }

        impl CommandRunner for OwnedListenerRunner {
            fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                let control_path = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-S").then(|| args[1].clone()))
                    .expect("control path");
                let operation = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-O").then(|| args[1].clone()))
                    .expect("operation");
                let value = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-L").then_some(args[1].as_str()))
                    .expect("forward value");
                let port = value
                    .split(':')
                    .nth(1)
                    .and_then(|port| port.parse::<u16>().ok())
                    .expect("scalar local port");
                self.operations.lock().expect("operations").push((
                    control_path.clone(),
                    operation.clone(),
                    port,
                ));
                let mut occupied = self.occupied.lock().expect("occupied listeners");
                match operation.as_str() {
                    "forward" if occupied.contains_key(&port) => ControlResult::BindFailed,
                    "forward" => {
                        occupied.insert(port, control_path);
                        ControlResult::Succeeded
                    }
                    "cancel" if occupied.get(&port) == Some(&control_path) => {
                        occupied.remove(&port);
                        ControlResult::Succeeded
                    }
                    "cancel" => ControlResult::Rejected,
                    _ => ControlResult::Rejected,
                }
            }

            fn cancel(&self) {}
        }

        let runner = Arc::new(OwnedListenerRunner {
            occupied: Mutex::new(BTreeMap::new()),
            operations: Mutex::new(Vec::new()),
        });
        let start_attachment =
            |control_path: &str, mappings: MappingRegistry| -> (BrokerServer, ForwardingClient) {
                let (parent, child) = UnixStream::pair().expect("broker pair");
                let broker = BrokerServer::start_with_runner_and_registry(
                    parent,
                    crate::platform::InheritedPeerIdentity::current_process(),
                    ControlAuthority::new("example".to_owned(), PathBuf::from(control_path)),
                    runner.clone(),
                    Duration::from_secs(10),
                    mappings,
                )
                .expect("broker server");
                let client =
                    ForwardingClient::from_stream_for_test(child, true).expect("client handshake");
                (broker, client)
            };

        let (old_mappings, _) = MappingRegistry::for_broker_test([]);
        let (_old_broker, old_client) = start_attachment("/tmp/herdr-old-control", old_mappings);
        let (new_mappings, candidate_calls) = MappingRegistry::for_broker_test([43_123]);
        let (_new_broker, new_client) = start_attachment("/tmp/herdr-new-control", new_mappings);

        assert_eq!(settle_forward(&old_client, spec()), Ok(8080));
        assert_eq!(settle_forward(&new_client, spec()), Ok(43_123));
        assert_eq!(candidate_calls.load(Ordering::SeqCst), 1);
        new_client
            .assert_policy(false)
            .expect("disable new attachment");
        assert_eq!(settle_forward(&old_client, spec()), Ok(8080));
        old_client
            .assert_policy(false)
            .expect("disable old attachment");

        assert!(runner
            .occupied
            .lock()
            .expect("occupied listeners")
            .is_empty());
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec![
                (
                    "/tmp/herdr-old-control".to_owned(),
                    "forward".to_owned(),
                    8080
                ),
                (
                    "/tmp/herdr-new-control".to_owned(),
                    "forward".to_owned(),
                    8080
                ),
                (
                    "/tmp/herdr-new-control".to_owned(),
                    "forward".to_owned(),
                    43_123,
                ),
                (
                    "/tmp/herdr-new-control".to_owned(),
                    "cancel".to_owned(),
                    43_123,
                ),
                (
                    "/tmp/herdr-old-control".to_owned(),
                    "cancel".to_owned(),
                    8080
                ),
            ]
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
    fn quarantined_preferred_port_does_not_hide_remapped_creating_or_ready_mappings() {
        let runner = Arc::new(RecordingRunner::with_delay(
            [
                ControlResult::Succeeded,
                ControlResult::Rejected,
                ControlResult::Succeeded,
                ControlResult::Succeeded,
                ControlResult::Succeeded,
            ],
            Duration::from_millis(30),
        ));
        let (mappings, candidate_calls) = MappingRegistry::for_broker_test([43_123]);
        let (parent, child) = UnixStream::pair().expect("broker pair");
        let _broker = BrokerServer::start_with_runner_and_registry(
            parent,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority(),
            runner.clone(),
            Duration::from_secs(10),
            mappings,
        )
        .expect("broker server");
        let client = ForwardingClient::from_stream_for_test(child, true).expect("client handshake");

        assert_eq!(
            client
                .begin_localhost(8080)
                .expect("partial preferred pair")
                .wait(),
            Err(ForwardFailure::AtomicCreationFailed)
        );
        assert_eq!(candidate_calls.load(Ordering::SeqCst), 0);

        let owner = client.begin_localhost(8080).expect("remapped owner");
        let joined = client.begin_localhost(8080).expect("concurrent waiter");
        assert_eq!(owner.wait(), Ok(43_123));
        assert_eq!(joined.wait(), Ok(43_123));
        assert_eq!(candidate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "forward", "forward"]
        );

        assert_eq!(
            client.begin_localhost(8080).expect("ready reuse").wait(),
            Ok(43_123)
        );
        assert_eq!(candidate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "forward", "forward"]
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

        let mut disable = client
            .begin_assert_policy(false, saved_limit(12))
            .expect("begin disable");
        assert_eq!(
            wait_for_policy(&mut disable),
            (false, saved_limit(12), Err(ForwardFailure::CommandRejected))
        );

        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward", "cancel", "cancel"]
        );
    }

    #[test]
    fn disabling_during_partial_pair_failure_retries_full_ordered_cleanup() {
        let (_broker, client, commands) = stepped_broker(saved_limit(12));
        let mut pair = client.begin_localhost(8080).expect("pair");
        let ipv4_forward = next_command(&commands);
        assert_eq!(ipv4_forward.operation(), "forward");
        assert!(ipv4_forward.forward_value().starts_with("127.0.0.1:"));
        ipv4_forward.settle(ControlResult::Succeeded);
        let ipv6_forward = next_command(&commands);
        assert_eq!(ipv6_forward.operation(), "forward");
        assert!(ipv6_forward.forward_value().starts_with("[::1]:"));

        let policy_client = client.clone();
        let disable = std::thread::spawn(move || {
            policy_client
                .begin_assert_policy(false, saved_limit(12))
                .expect("begin disable")
                .wait()
        });
        assert_eq!(wait_for_mapping(&mut pair), Err(ForwardFailure::Cancelled));
        ipv6_forward.settle(ControlResult::Rejected);

        let rollback = next_command(&commands);
        assert_eq!(rollback.operation(), "cancel");
        assert!(rollback.forward_value().starts_with("127.0.0.1:"));
        rollback.settle(ControlResult::Rejected);
        let policy_ipv4 = next_command(&commands);
        assert_eq!(policy_ipv4.operation(), "cancel");
        assert!(policy_ipv4.forward_value().starts_with("127.0.0.1:"));
        policy_ipv4.settle(ControlResult::Succeeded);
        let policy_ipv6 = next_command(&commands);
        assert_eq!(policy_ipv6.operation(), "cancel");
        assert!(policy_ipv6.forward_value().starts_with("[::1]:"));
        policy_ipv6.settle(ControlResult::Rejected);

        assert_eq!(
            disable
                .join()
                .expect("disable thread")
                .expect("disable acknowledgement"),
            (false, saved_limit(12), Err(ForwardFailure::CommandRejected))
        );
    }

    #[test]
    fn normal_teardown_closes_pending_work_reaps_control_and_skips_mapping_cancellation() {
        struct TeardownRunner {
            calls: AtomicUsize,
            operations: Mutex<Vec<String>>,
            started: mpsc::SyncSender<()>,
            cancelled: AtomicBool,
            reaped: mpsc::SyncSender<()>,
        }

        impl CommandRunner for TeardownRunner {
            fn run(&self, invocation: &ControlInvocation, _timeout: Duration) -> ControlResult {
                let operation = invocation
                    .args
                    .windows(2)
                    .find_map(|args| (args[0] == "-O").then(|| args[1].clone()))
                    .expect("operation");
                self.operations.lock().expect("operations").push(operation);
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return ControlResult::Succeeded;
                }
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
        let runner = Arc::new(TeardownRunner {
            calls: AtomicUsize::new(0),
            operations: Mutex::new(Vec::new()),
            started: started_tx,
            cancelled: AtomicBool::new(false),
            reaped: reaped_tx,
        });
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
        assert_eq!(settle_forward(&client, spec_for_port(8080)), Ok(8080));
        let active = client
            .begin_forward(spec_for_port(8081))
            .expect("active mapping");
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("control command started");

        let started = std::time::Instant::now();
        broker.close();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(active.wait(), Err(ForwardFailure::CapabilityClosed));
        reaped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("control command reaped");
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "forward"]
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
        assert_eq!(settle_forward(&client, spec_for_port(8080)), Ok(8080));
        assert_eq!(settle_forward(&client, spec_for_port(8081)), Ok(8081));

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
                saved_mapping_limit: crate::config::SavedPortForwardLimit::DEFAULT.get(),
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
                saved_mapping_limit: crate::config::SavedPortForwardLimit::DEFAULT.get(),
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
            ServerMessage::ForwardSettled {
                result: Ok(8080),
                ..
            }
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

        for (offset, call) in calls.into_iter().enumerate() {
            assert_eq!(
                call.join().expect("call thread"),
                Ok(8100 + u16::try_from(offset).expect("bounded offset"))
            );
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

        assert_eq!(running.wait(), Ok(8080));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn disable_skips_queued_mapping_before_runner_invocation_and_settles_once() {
        let (_broker, client, commands) = stepped_broker(saved_limit(12));
        let mut active = client
            .begin_forward(spec_for_port(8080))
            .expect("active mapping");
        let active_command = next_command(&commands);
        assert_eq!(active_command.operation(), "forward");
        assert!(active_command.forward_value().contains(":8080:"));
        let mut queued = client
            .begin_forward(spec_for_port(8081))
            .expect("queued mapping");
        let mut disable = client
            .begin_assert_policy(false, saved_limit(12))
            .expect("begin disable");

        assert_eq!(
            wait_for_mapping(&mut active),
            Err(ForwardFailure::Cancelled)
        );
        assert_eq!(
            wait_for_mapping(&mut queued),
            Err(ForwardFailure::Cancelled)
        );
        active_command.settle(ControlResult::Succeeded);

        let cleanup = next_command(&commands);
        assert_eq!(cleanup.operation(), "cancel");
        assert!(cleanup.forward_value().contains(":8080:"));
        cleanup.settle(ControlResult::Succeeded);

        assert_eq!(
            wait_for_policy(&mut disable),
            (false, saved_limit(12), Ok(()))
        );
        assert_eq!(disable.try_wait(), None);
        assert!(matches!(
            commands.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(!client.is_active());
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
    fn in_flight_cancellation_failure_reports_incomplete_disable_cleanup() {
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
        let disable = std::thread::spawn(move || {
            policy_client
                .begin_assert_policy(false, saved_limit(12))
                .expect("begin disable")
                .wait()
        });

        assert_eq!(call.wait(), Err(ForwardFailure::Cancelled));
        assert_eq!(
            disable
                .join()
                .expect("disable thread")
                .expect("disable acknowledgement"),
            (false, saved_limit(12), Err(ForwardFailure::CommandRejected))
        );
        assert!(!client.is_active());
        assert_eq!(
            *runner.operations.lock().expect("operations"),
            vec!["forward", "cancel"]
        );
    }

    #[test]
    fn managed_master_death_closes_all_waiters_and_invalidates_ready_reuse() {
        let (_broker, client, commands) = stepped_broker(saved_limit(12));
        let mut ready = client.begin_forward(spec()).expect("ready mapping");
        next_command(&commands).settle(ControlResult::Succeeded);
        assert_eq!(wait_for_mapping(&mut ready), Ok(8080));

        let mut active = client
            .begin_forward(spec_for_port(8081))
            .expect("active mapping");
        let mut queued = client
            .begin_localhost(8082)
            .expect("queued localhost mapping");
        next_command(&commands).settle(ControlResult::MasterDied);

        assert_eq!(
            wait_for_mapping(&mut active),
            Err(ForwardFailure::CapabilityClosed)
        );
        assert_eq!(
            wait_for_mapping(&mut queued),
            Err(ForwardFailure::CapabilityClosed)
        );
        assert!(matches!(
            client.begin_forward(spec()),
            Err(ForwardFailure::CapabilityClosed)
        ));
    }

    #[test]
    fn channel_loss_has_scalar_and_localhost_call_parity() {
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
        let scalar = client.begin_forward(spec()).expect("begin scalar");
        let localhost = client.begin_localhost(8081).expect("begin localhost");

        broker.close();

        assert_eq!(scalar.wait(), Err(ForwardFailure::CapabilityClosed));
        assert_eq!(localhost.wait(), Err(ForwardFailure::CapabilityClosed));
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
