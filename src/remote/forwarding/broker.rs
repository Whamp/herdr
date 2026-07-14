use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use super::protocol::{
    self, ClientMessage, CorrelationId, ForwardFailure, ForwardSpec, ServerMessage,
    BROKER_PROTOCOL_VERSION,
};
use super::registry::{
    MappingAttempt, MappingControlResult, MappingRegistry, MappingRequest, MappingSettlement,
    WaiterCancellation,
};
use super::transport::AuthenticatedFrameReader;
use super::worker::{CommandRunner, ControlAuthority, ControlResult, ControlWorker, WorkerJob};

const MAX_PENDING_FORWARD_REQUESTS: usize = 32;

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

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::Acquire) && !self.inner.closed.load(Ordering::Acquire)
    }

    pub(crate) fn assert_policy(&self, enabled: bool) -> io::Result<()> {
        let (effective, result) = self.begin_assert_policy(enabled)?.wait()?;
        self.inner.active.store(effective, Ordering::Release);
        result.map_err(|_| io::Error::other("forwarding broker policy update failed"))
    }

    pub(crate) fn begin_assert_policy(&self, enabled: bool) -> io::Result<PolicyCall> {
        let (id, receiver) = self.start_call(PendingKind::Policy, |id| {
            ClientMessage::AssertPolicy { id, enabled }
        })?;
        Ok(PolicyCall {
            requested: enabled,
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
            .ok_or(ForwardFailure::CapabilityClosed);
        self.settled = true;
        response
    }

    fn try_wait(&mut self) -> Option<Result<ServerMessage, ForwardFailure>> {
        let response = match self.receiver.as_ref()?.try_recv() {
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

    fn set_active(&self, active: bool) {
        self.inner.active.store(active, Ordering::Release);
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
    core: BrokerCallCore,
}

impl PolicyCall {
    fn wait(mut self) -> io::Result<(bool, Result<(), ForwardFailure>)> {
        let response = self.core.wait().ok();
        let settled = policy_response(self.requested, response)?;
        self.core.set_active(settled.0);
        Ok(settled)
    }

    pub(crate) fn try_wait(&mut self) -> Option<(bool, Result<(), ForwardFailure>)> {
        let response = match self.core.try_wait()? {
            Ok(response) => Some(response),
            Err(ForwardFailure::CapabilityClosed) => {
                return Some((false, Err(ForwardFailure::CapabilityClosed)));
            }
            Err(error) => return Some((false, Err(error))),
        };
        let settled = policy_response(self.requested, response)
            .unwrap_or((false, Err(ForwardFailure::CapabilityClosed)));
        self.core.set_active(settled.0);
        Some(settled)
    }

    pub(crate) fn cancel(&mut self) {
        self.core.cancel();
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
enum QueuedJobKind {
    Mapping(MappingAttempt),
    Cleanup,
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
    let mut pending_disable_ack = None;

    'broker: loop {
        while let Ok(result) = worker.try_recv() {
            let Some(completed) = active.take() else {
                break 'broker;
            };
            if completed.job.id != result.id || completed.job.operation != result.operation {
                break 'broker;
            }

            match completed.kind {
                QueuedJobKind::Mapping(attempt) => {
                    let Some(control_result) = mapping_control_result(result.result) else {
                        break 'broker;
                    };
                    let completion = mappings.complete(attempt, control_result);
                    if let Some(next) = completion.attempt {
                        queue.push_front(mapping_job(next));
                    }
                    if let Some(cancelled) = completion.cancellation {
                        queue.push_front(cleanup_job(cancelled));
                    }
                    for settlement in completion.settlements {
                        if write_mapping_settlement(&mut stream, attempt.is_localhost(), settlement)
                            .is_err()
                        {
                            break 'broker;
                        }
                    }
                }
                QueuedJobKind::Cleanup => {}
            }
            if dispatch_next(&worker, &mut mappings, &mut queue, &mut active).is_err() {
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
                            for revoked in mappings.revoke_creating() {
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
                            if active.is_none()
                                && dispatch_next(&worker, &mut mappings, &mut queue, &mut active)
                                    .is_err()
                            {
                                break 'broker;
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
                            if write_mapping_settlement(
                                &mut stream,
                                false,
                                MappingSettlement::failed(id, ForwardFailure::Disabled),
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        let at_limit = mappings.waiter_count() >= MAX_PENDING_FORWARD_REQUESTS;
                        let request =
                            mappings.request_scalar(id, spec.remote_address, spec.remote_port);
                        if at_limit && matches!(request, MappingRequest::Pending { .. }) {
                            let _ = mappings.cancel_waiter(id);
                            if write_mapping_settlement(
                                &mut stream,
                                false,
                                MappingSettlement::failed(id, ForwardFailure::TooManyRequests),
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if handle_mapping_request(
                            &worker,
                            &mut stream,
                            &mut mappings,
                            &mut queue,
                            &mut active,
                            false,
                            request,
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
                        if state == BrokerState::Disabled {
                            if write_mapping_settlement(
                                &mut stream,
                                true,
                                MappingSettlement::failed(id, ForwardFailure::Disabled),
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        let at_limit = mappings.waiter_count() >= MAX_PENDING_FORWARD_REQUESTS;
                        let request = mappings.request_localhost(id, remote_port);
                        if at_limit && matches!(request, MappingRequest::Pending { .. }) {
                            let _ = mappings.cancel_waiter(id);
                            if write_mapping_settlement(
                                &mut stream,
                                true,
                                MappingSettlement::failed(id, ForwardFailure::TooManyRequests),
                            )
                            .is_err()
                            {
                                break 'broker;
                            }
                            continue;
                        }
                        if handle_mapping_request(
                            &worker,
                            &mut stream,
                            &mut mappings,
                            &mut queue,
                            &mut active,
                            true,
                            request,
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
        kind: QueuedJobKind::Cleanup,
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
        ControlResult::PairCancellationSucceeded | ControlResult::PairCancellationFailed => None,
    }
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

        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        assert_eq!(settle_forward(&client, spec()), Ok(8080));
        client.assert_policy(false).expect("disable policy");
        client.assert_policy(true).expect("re-enable policy");
        assert_eq!(settle_forward(&client, spec()), Ok(8080));

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
