//! Blocking client socket transport for the headless server.
//!
//! This module owns the thin-client handshake, read loop, and writer loop.
//! It converts socket I/O into [`ServerEvent`] values consumed by
//! `HeadlessServer`.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SendError, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;
use interprocess::TryClone as _;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::ipc::LocalStream;
use crate::protocol::{
    self, AttachScrollDirection, AttachScrollSource, ClientInputEvent, ClientKeybindings,
    ClientLaunchMode, ClientMessage, RenderEncoding, ServerMessage, MAX_CLIPBOARD_IMAGE_PAYLOAD,
    MAX_FRAME_SIZE, MAX_GRAPHICS_FRAME_SIZE, PROTOCOL_VERSION,
};

/// Minimum accepted attached client size.
///
/// Narrow observers must be allowed to drive narrow renders, otherwise the
/// server wraps pane content against a wider width and the client sees the
/// right edge clipped.
const MIN_CLIENT_COLS: u16 = 1;
const MIN_CLIENT_ROWS: u16 = 1;

/// How long to wait for a client handshake before closing the connection.
/// Set to 4 seconds (rather than 5) to guarantee the connection is closed
/// within the 5-second deadline, even with OS timer slack, thread scheduling,
/// and cleanup overhead.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

/// Maximum input payload size (bytes) for a single `ClientMessage::Input`.
const MAX_INPUT_PAYLOAD: usize = 1024 * 1024; // 1 MB
/// Maximum structured input events accepted in one client message.
const MAX_INPUT_EVENT_BATCH: usize = 4096;

/// Channels owned by the server side of a client writer thread.
#[derive(Clone, Debug)]
pub(crate) struct ClientWriter {
    /// Reliable control messages such as shutdown, notifications, and clipboard writes.
    pub(crate) control: ClientControlWriter,
    /// Droppable render messages. Capacity is one so slow clients cannot build lag.
    pub(crate) render: ClientRenderWriter,
}

#[cfg(test)]
impl ClientWriter {
    pub(crate) fn test_channel(
        control: std::sync::mpsc::Sender<Vec<u8>>,
        render: std::sync::mpsc::SyncSender<Vec<u8>>,
    ) -> Self {
        Self {
            control: ClientControlWriter {
                target: ClientControlTarget::Channel(control),
            },
            render: ClientRenderWriter {
                target: ClientRenderTarget::Channel(render),
            },
        }
    }

    pub(crate) fn send_barrier_for_test(&self, data: Vec<u8>) -> Result<(), Vec<u8>> {
        match &self.control.target {
            ClientControlTarget::Queue(queue) => queue.send_barrier_if_empty(data),
            ClientControlTarget::Channel(_) => Err(data),
        }
    }

    pub(crate) fn block_next_render_write_for_test(&self) -> Option<ClientRenderWriteBlock> {
        match &self.render.target {
            ClientRenderTarget::Queue(queue) => Some(queue.block_next_render_write_for_test()),
            ClientRenderTarget::Channel(_) => None,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestRenderWriteGateState {
    entered: bool,
    released: bool,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestRenderWriteGate {
    state: Mutex<TestRenderWriteGateState>,
    changed: Condvar,
}

#[cfg(test)]
impl TestRenderWriteGate {
    fn wait_before_write(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ClientRenderWriteBlock {
    gate: Arc<TestRenderWriteGate>,
}

#[cfg(test)]
impl ClientRenderWriteBlock {
    pub(crate) fn wait_until_blocked(&self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.entered {
            state = self
                .gate
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    pub(crate) fn release(self) {
        drop(self);
    }
}

#[cfg(test)]
impl Drop for ClientRenderWriteBlock {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.released = true;
        self.gate.changed.notify_all();
    }
}

#[derive(Debug)]
pub(crate) struct ClientControlWriter {
    target: ClientControlTarget,
}

#[derive(Debug)]
enum ClientControlTarget {
    Queue(Arc<ClientWriterQueue>),
    #[cfg(test)]
    Channel(std::sync::mpsc::Sender<Vec<u8>>),
}

#[derive(Debug)]
pub(crate) struct ClientRenderWriter {
    target: ClientRenderTarget,
}

#[derive(Debug)]
enum ClientRenderTarget {
    Queue(Arc<ClientWriterQueue>),
    #[cfg(test)]
    Channel(std::sync::mpsc::SyncSender<Vec<u8>>),
}

impl Clone for ClientControlWriter {
    fn clone(&self) -> Self {
        match &self.target {
            ClientControlTarget::Queue(queue) => {
                queue.add_sender();
                Self {
                    target: ClientControlTarget::Queue(queue.clone()),
                }
            }
            #[cfg(test)]
            ClientControlTarget::Channel(sender) => Self {
                target: ClientControlTarget::Channel(sender.clone()),
            },
        }
    }
}

impl Drop for ClientControlWriter {
    fn drop(&mut self) {
        match &self.target {
            ClientControlTarget::Queue(queue) => queue.remove_sender(),
            #[cfg(test)]
            ClientControlTarget::Channel(_) => {}
        }
    }
}

impl ClientControlWriter {
    fn queue(queue: Arc<ClientWriterQueue>) -> Self {
        queue.add_sender();
        Self {
            target: ClientControlTarget::Queue(queue),
        }
    }

    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        match &self.target {
            ClientControlTarget::Queue(queue) => queue.send_control(data),
            #[cfg(test)]
            ClientControlTarget::Channel(sender) => sender.send(data),
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn fail_next_send_for_test(&self) {
        match &self.target {
            ClientControlTarget::Queue(queue) => queue.close_writer(),
            #[cfg(test)]
            ClientControlTarget::Channel(_) => {}
        }
    }
}

impl Clone for ClientRenderWriter {
    fn clone(&self) -> Self {
        match &self.target {
            ClientRenderTarget::Queue(queue) => {
                queue.add_sender();
                Self {
                    target: ClientRenderTarget::Queue(queue.clone()),
                }
            }
            #[cfg(test)]
            ClientRenderTarget::Channel(sender) => Self {
                target: ClientRenderTarget::Channel(sender.clone()),
            },
        }
    }
}

impl Drop for ClientRenderWriter {
    fn drop(&mut self) {
        match &self.target {
            ClientRenderTarget::Queue(queue) => queue.remove_sender(),
            #[cfg(test)]
            ClientRenderTarget::Channel(_) => {}
        }
    }
}

impl ClientRenderWriter {
    fn queue(queue: Arc<ClientWriterQueue>) -> Self {
        queue.add_sender();
        Self {
            target: ClientRenderTarget::Queue(queue),
        }
    }

    pub(crate) fn try_send(&self, data: Vec<u8>) -> Result<(), TrySendError<Vec<u8>>> {
        self.try_send_inner(data, None)
    }

    pub(crate) fn try_send_with_write_notification(
        &self,
        data: Vec<u8>,
        acknowledgement: crate::server::client_projection::ClientFrameAcknowledgement,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        self.try_send_inner(data, Some(acknowledgement))
    }

    fn try_send_inner(
        &self,
        data: Vec<u8>,
        acknowledgement: Option<crate::server::client_projection::ClientFrameAcknowledgement>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        match &self.target {
            ClientRenderTarget::Queue(queue) => queue.try_send_render(data, acknowledgement),
            #[cfg(test)]
            ClientRenderTarget::Channel(sender) => sender.try_send(data),
        }
    }
}

#[derive(Debug)]
struct ClientWriterQueue {
    state: Mutex<ClientWriterQueueState>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct ClientWriterQueueState {
    control: VecDeque<Vec<u8>>,
    render: Option<QueuedRender>,
    senders: usize,
    writer_alive: bool,
    #[cfg(test)]
    next_render_write_gate: Option<Arc<TestRenderWriteGate>>,
}

#[derive(Debug, PartialEq, Eq)]
struct QueuedRender {
    data: Vec<u8>,
    acknowledgement: Option<crate::server::client_projection::ClientFrameAcknowledgement>,
}

#[derive(Debug, PartialEq, Eq)]
enum ClientWriteItem {
    Control(Vec<u8>),
    Render(QueuedRender),
}

impl ClientWriterQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ClientWriterQueueState {
                writer_alive: true,
                ..ClientWriterQueueState::default()
            }),
            ready: Condvar::new(),
        })
    }

    fn add_sender(&self) {
        let mut state = self.lock_state();
        state.senders = state.senders.saturating_add(1);
    }

    fn remove_sender(&self) {
        let mut state = self.lock_state();
        state.senders = state.senders.saturating_sub(1);
        self.ready.notify_one();
    }

    fn send_control(&self, data: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        let mut state = self.lock_state();
        if !state.writer_alive {
            return Err(SendError(data));
        }
        state.control.push_back(data);
        self.ready.notify_one();
        Ok(())
    }

    #[cfg(test)]
    fn send_barrier_if_empty(&self, data: Vec<u8>) -> Result<(), Vec<u8>> {
        let mut state = self.lock_state();
        if !state.writer_alive || !state.control.is_empty() || state.render.is_some() {
            return Err(data);
        }
        state.control.push_back(data);
        self.ready.notify_one();
        Ok(())
    }

    #[cfg(test)]
    fn block_next_render_write_for_test(&self) -> ClientRenderWriteBlock {
        let gate = Arc::new(TestRenderWriteGate::default());
        let mut state = self.lock_state();
        assert!(
            state.next_render_write_gate.replace(gate.clone()).is_none(),
            "only one render write may be blocked at a time"
        );
        ClientRenderWriteBlock { gate }
    }

    #[cfg(test)]
    fn wait_before_render_write_for_test(&self) {
        let gate = self.lock_state().next_render_write_gate.take();
        if let Some(gate) = gate {
            gate.wait_before_write();
        }
    }

    fn try_send_render(
        &self,
        data: Vec<u8>,
        acknowledgement: Option<crate::server::client_projection::ClientFrameAcknowledgement>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        let mut state = self.lock_state();
        if !state.writer_alive {
            return Err(TrySendError::Disconnected(data));
        }
        if state.render.is_some() {
            return Err(TrySendError::Full(data));
        }
        state.render = Some(QueuedRender {
            data,
            acknowledgement,
        });
        self.ready.notify_one();
        Ok(())
    }

    fn recv(&self) -> Option<ClientWriteItem> {
        let mut state = self.lock_state();
        loop {
            if let Some(data) = state.control.pop_front() {
                return Some(ClientWriteItem::Control(data));
            }
            if let Some(render) = state.render.take() {
                self.ready.notify_one();
                return Some(ClientWriteItem::Render(render));
            }
            if state.senders == 0 {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn close_writer(&self) {
        let mut state = self.lock_state();
        state.writer_alive = false;
        self.ready.notify_all();
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ClientWriterQueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Internal event sent from client transport threads to the main event loop.
#[derive(Debug)]
pub(crate) enum ServerEvent {
    /// A new client completed the handshake.
    ClientConnected {
        client_id: u64,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
        render_encoding: RenderEncoding,
        keybindings: Option<Box<crate::config::LiveKeybindConfig>>,
        direct_attach_requested: bool,
        external_open_policy: Option<crate::protocol::ExternalOpenPolicy>,
        external_open_attachment_id: Option<crate::protocol::ExternalOpenAttachmentId>,
        writer: ClientWriter,
    },
    /// A client sent an input message.
    ClientInput { client_id: u64, data: Vec<u8> },
    /// A client sent structured input events.
    ClientInputEvents {
        client_id: u64,
        events: Vec<crate::protocol::ClientInputEvent>,
    },
    /// A full app client replaced its effective device-local external-open policy.
    ExternalOpenPolicyUpdate {
        client_id: u64,
        policy: crate::protocol::ExternalOpenPolicy,
    },
    /// A full app client reported a source-bound device-local policy mutation result.
    ExternalOpenPolicyMutationResult {
        client_id: u64,
        request_id: u64,
        requested_policy: crate::protocol::ExternalOpenPolicy,
        persisted_policy: Option<crate::protocol::ExternalOpenPolicy>,
        effective_policy: crate::protocol::ExternalOpenPolicy,
        failure_stage: Option<crate::protocol::ExternalOpenPolicyMutationFailureStage>,
    },
    /// A full app client failed to reload its device-local policy explicitly.
    ExternalOpenPolicyReloadFailed {
        client_id: u64,
        effective_policy: crate::protocol::ExternalOpenPolicy,
        cleanup_incomplete: bool,
    },
    /// A full app client completed external-open preparation.
    ExternalOpenReady {
        client_id: u64,
        request_id: u64,
        target: crate::protocol::ExternalOpenTarget,
    },
    /// A full app client failed external-open preparation.
    ExternalOpenPreparationFailed {
        client_id: u64,
        request_id: u64,
        reason: crate::protocol::ExternalOpenPreparationFailure,
    },
    /// A full app client reported the result of a committed external open.
    ExternalOpenResult {
        client_id: u64,
        request_id: u64,
        result: crate::protocol::ExternalOpenResult,
    },
    /// A client sent local clipboard image bytes to paste into a remote pane.
    ClientClipboardImage {
        client_id: u64,
        extension: String,
        data: Vec<u8>,
    },
    /// A client requested direct attach to one terminal.
    ClientAttachTerminal {
        client_id: u64,
        terminal_id: String,
        takeover: bool,
    },
    /// A client requested read-only observation of one terminal.
    ClientObserveTerminal { client_id: u64, target: String },
    /// A client requested writable control of one terminal.
    ClientControlTerminal {
        client_id: u64,
        target: String,
        takeover: bool,
    },
    /// A direct terminal attach client requested scrollback movement.
    ClientAttachScroll {
        client_id: u64,
        source: AttachScrollSource,
        direction: AttachScrollDirection,
        lines: u16,
        column: Option<u16>,
        row: Option<u16>,
        modifiers: u8,
    },
    /// A client sent a resize message.
    ClientResize {
        client_id: u64,
        cols: u16,
        rows: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    },
    /// A client detached gracefully.
    ClientDetach { client_id: u64 },
    /// A client connection was lost.
    ClientDisconnected { client_id: u64 },
    /// A client writer drained its render slot and can accept another render.
    ClientWriterDrained { client_id: u64 },
    /// One exact queued client frame was written successfully to its socket.
    ClientFrameWritten {
        client_id: u64,
        acknowledgement: crate::server::client_projection::ClientFrameAcknowledgement,
    },
    /// A client writer could not deliver queued bytes to its socket.
    ClientWriterFailed { client_id: u64 },
    /// Ctrl+C or external shutdown signal received.
    QuitSignal,
}

/// Clamp client-reported terminal dimensions to a minimum viable size.
pub(crate) fn clamp_terminal_size(cols: u16, rows: u16) -> (u16, u16) {
    let clamped_cols = cols.max(MIN_CLIENT_COLS);
    let clamped_rows = rows.max(MIN_CLIENT_ROWS);
    (clamped_cols, clamped_rows)
}

fn parse_client_keybindings(
    keybindings: ClientKeybindings,
) -> Result<Option<Box<crate::config::LiveKeybindConfig>>, String> {
    match keybindings {
        ClientKeybindings::Server => Ok(None),
        ClientKeybindings::Local { keys_toml } => {
            let mut config = toml::from_str::<crate::config::Config>(&keys_toml)
                .map_err(|err| format!("invalid client keybindings: {err}"))?;
            config.keys.command.clear();
            Ok(Some(Box::new(crate::config::LiveKeybindConfig {
                prefix: config.prefix_key(),
                keybinds: config.keybinds(),
            })))
        }
    }
}

fn input_events_within_limits(events: &[ClientInputEvent]) -> bool {
    if events.len() > MAX_INPUT_EVENT_BATCH {
        return false;
    }

    let mut paste_bytes = 0usize;
    for event in events {
        if let ClientInputEvent::Paste { text } = event {
            paste_bytes = paste_bytes.saturating_add(text.len());
            if paste_bytes > MAX_INPUT_PAYLOAD {
                return false;
            }
        }
    }

    true
}

#[cfg(windows)]
fn set_client_recv_timeout(
    stream: &LocalStream,
    timeout: Option<Duration>,
    context: &'static str,
    client_id: u64,
) -> io::Result<()> {
    match stream.set_recv_timeout(timeout) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::Unsupported => {
            debug!(client_id, err = %err, context, "client socket receive timeout unavailable");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

#[cfg(not(windows))]
fn set_client_recv_timeout(
    stream: &LocalStream,
    timeout: Option<Duration>,
    _context: &'static str,
    _client_id: u64,
) -> io::Result<()> {
    stream.set_recv_timeout(timeout)
}

/// Handles the client handshake on a blocking thread.
///
/// Reads the `Hello` message, validates the version, sends `Welcome`,
/// and then enters a read loop forwarding messages to the server event channel.
pub(crate) fn handle_client_handshake(
    mut stream: LocalStream,
    client_id: u64,
    server_event_tx: &mpsc::Sender<ServerEvent>,
    should_quit: &Arc<AtomicBool>,
) -> io::Result<()> {
    // Reset to blocking mode — the accept loop sets nonblocking but
    // the handshake thread needs blocking I/O for read_message/write_message.
    stream.set_nonblocking(false)?;

    set_client_recv_timeout(
        &stream,
        Some(HANDSHAKE_TIMEOUT),
        "client handshake read timeout unavailable",
        client_id,
    )?;

    // Read the Hello message.
    let hello: ClientMessage = match protocol::read_message(&mut stream, MAX_FRAME_SIZE) {
        Ok(msg) => msg,
        Err(protocol::FramingError::UnexpectedEof) => {
            debug!(client_id, "client disconnected before handshake");
            return Ok(());
        }
        Err(protocol::FramingError::Oversized { claimed, max }) => {
            warn!(client_id, claimed, max, "oversized handshake from client");
            return Ok(());
        }
        Err(err) => {
            debug!(client_id, err = %err, "failed to read client hello");
            return Ok(());
        }
    };

    let (
        client_cols,
        client_rows,
        cell_width_px,
        cell_height_px,
        render_encoding,
        keybindings,
        direct_attach_requested,
        external_open_policy,
        external_open_attachment_id,
    ) = match hello {
        ClientMessage::Hello {
            version,
            cols,
            rows,
            cell_width_px,
            cell_height_px,
            requested_encoding,
            keybindings,
            launch_mode,
            external_open_policy,
            external_open_attachment_id,
        } => {
            // Version check.
            match protocol::check_client_version(version) {
                protocol::VersionCheck::Compatible => {}
                protocol::VersionCheck::Incompatible(reason) => {
                    // Send rejection Welcome.
                    let welcome = ServerMessage::Welcome {
                        version: PROTOCOL_VERSION,
                        encoding: RenderEncoding::SemanticFrame,
                        error: Some(reason),
                    };
                    let _ = protocol::write_message(&mut stream, &welcome);
                    return Ok(());
                }
            }

            let keybindings = match parse_client_keybindings(keybindings) {
                Ok(keybindings) => keybindings,
                Err(error) => {
                    let welcome = ServerMessage::Welcome {
                        version: PROTOCOL_VERSION,
                        encoding: RenderEncoding::SemanticFrame,
                        error: Some(error),
                    };
                    let _ = protocol::write_message(&mut stream, &welcome);
                    return Ok(());
                }
            };

            let direct_attach_requested = match (
                launch_mode,
                external_open_policy,
                external_open_attachment_id,
            ) {
                (ClientLaunchMode::App, Some(_), Some(_)) => false,
                (ClientLaunchMode::TerminalAttach, None, None) => true,
                (ClientLaunchMode::App, None, _) => {
                    let welcome = ServerMessage::Welcome {
                        version: PROTOCOL_VERSION,
                        encoding: RenderEncoding::SemanticFrame,
                        error: Some(
                            "full app client must advertise external-open policy".to_owned(),
                        ),
                    };
                    let _ = protocol::write_message(&mut stream, &welcome);
                    return Ok(());
                }
                (ClientLaunchMode::App, Some(_), None) => {
                    let welcome = ServerMessage::Welcome {
                        version: PROTOCOL_VERSION,
                        encoding: RenderEncoding::SemanticFrame,
                        error: Some(
                            "full app client must advertise external-open attachment identity"
                                .to_owned(),
                        ),
                    };
                    let _ = protocol::write_message(&mut stream, &welcome);
                    return Ok(());
                }
                (ClientLaunchMode::TerminalAttach, _, _) => {
                    let welcome = ServerMessage::Welcome {
                        version: PROTOCOL_VERSION,
                        encoding: RenderEncoding::SemanticFrame,
                        error: Some(
                            "terminal connection must not advertise external-open policy"
                                .to_owned(),
                        ),
                    };
                    let _ = protocol::write_message(&mut stream, &welcome);
                    return Ok(());
                }
            };

            // Clamp size.
            let (clamped_cols, clamped_rows) = clamp_terminal_size(cols, rows);
            (
                clamped_cols,
                clamped_rows,
                cell_width_px,
                cell_height_px,
                requested_encoding,
                keybindings,
                direct_attach_requested,
                external_open_policy,
                external_open_attachment_id,
            )
        }
        _ => {
            // First message must be Hello.
            debug!(client_id, "first message was not Hello, closing");
            let welcome = ServerMessage::Welcome {
                version: PROTOCOL_VERSION,
                encoding: RenderEncoding::SemanticFrame,
                error: Some("expected Hello as first message".to_owned()),
            };
            let _ = protocol::write_message(&mut stream, &welcome);
            return Ok(());
        }
    };

    // Send Welcome.
    let welcome = ServerMessage::Welcome {
        version: PROTOCOL_VERSION,
        encoding: render_encoding,
        error: None,
    };
    protocol::write_message(&mut stream, &welcome).map_err(|e| io::Error::other(e.to_string()))?;

    set_client_recv_timeout(
        &stream,
        None,
        "failed to clear client handshake read timeout",
        client_id,
    )?;

    // Create separate channels for reliable control messages and droppable renders.
    let writer_queue = ClientWriterQueue::new();
    let writer = ClientWriter {
        control: ClientControlWriter::queue(writer_queue.clone()),
        render: ClientRenderWriter::queue(writer_queue.clone()),
    };

    // Spawn a writer thread that forwards messages from the channels to the stream.
    let write_stream = stream.try_clone()?;
    let writer_event_tx = server_event_tx.clone();
    std::thread::spawn(move || {
        client_writer_loop(write_stream, client_id, writer_queue, writer_event_tx);
    });

    // Notify the main loop about the new client.
    let _ = server_event_tx.blocking_send(ServerEvent::ClientConnected {
        client_id,
        cols: client_cols,
        rows: client_rows,
        cell_width_px,
        cell_height_px,
        render_encoding,
        keybindings,
        direct_attach_requested,
        external_open_policy,
        external_open_attachment_id,
        writer,
    });

    // Enter read loop — read client messages and forward to main loop.
    client_read_loop(stream, client_id, server_event_tx, should_quit)
}

/// The client writer loop — prioritizes control messages over render frames.
fn client_writer_loop(
    mut stream: LocalStream,
    client_id: u64,
    writer_queue: Arc<ClientWriterQueue>,
    server_event_tx: mpsc::Sender<ServerEvent>,
) {
    let mut write_failed = false;
    while let Some(item) = writer_queue.recv() {
        match item {
            ClientWriteItem::Control(data) => {
                if !write_framed_bytes(&mut stream, &data) {
                    write_failed = true;
                    break;
                }
            }
            ClientWriteItem::Render(render) => {
                let _ =
                    server_event_tx.blocking_send(ServerEvent::ClientWriterDrained { client_id });
                #[cfg(test)]
                writer_queue.wait_before_render_write_for_test();
                if !write_framed_bytes(&mut stream, &render.data) {
                    write_failed = true;
                    break;
                }
                if let Some(acknowledgement) = render.acknowledgement {
                    let _ = server_event_tx.blocking_send(ServerEvent::ClientFrameWritten {
                        client_id,
                        acknowledgement,
                    });
                }
            }
        }
    }
    writer_queue.close_writer();
    if write_failed {
        let _ = server_event_tx.blocking_send(ServerEvent::ClientWriterFailed { client_id });
    }
    debug!("client writer thread exiting");
}

fn write_framed_bytes(stream: &mut LocalStream, data: &[u8]) -> bool {
    if let Err(err) = stream.write_all(data) {
        debug!(err = %err, "client write failed, closing writer");
        return false;
    }
    if let Err(err) = stream.flush() {
        debug!(err = %err, "client flush failed, closing writer");
        return false;
    }
    true
}

/// The client read loop — reads messages from the client and forwards to the server event channel.
fn client_read_loop(
    mut stream: LocalStream,
    client_id: u64,
    server_event_tx: &mpsc::Sender<ServerEvent>,
    should_quit: &Arc<AtomicBool>,
) -> io::Result<()> {
    while !should_quit.load(Ordering::Acquire) {
        let msg: ClientMessage = match protocol::read_message(&mut stream, MAX_GRAPHICS_FRAME_SIZE)
        {
            Ok(msg) => msg,
            Err(protocol::FramingError::UnexpectedEof) => {
                // Client disconnected.
                let _ =
                    server_event_tx.blocking_send(ServerEvent::ClientDisconnected { client_id });
                break;
            }
            Err(protocol::FramingError::Oversized { claimed, max }) => {
                warn!(
                    client_id,
                    claimed, max, "oversized message from client, closing"
                );
                let _ =
                    server_event_tx.blocking_send(ServerEvent::ClientDisconnected { client_id });
                break;
            }
            Err(err) => {
                debug!(client_id, err = %err, "client read error, closing");
                let _ =
                    server_event_tx.blocking_send(ServerEvent::ClientDisconnected { client_id });
                break;
            }
        };

        let event = match msg {
            ClientMessage::Input { data } => {
                // Validate input size.
                if data.len() > MAX_INPUT_PAYLOAD {
                    warn!(
                        client_id,
                        size = data.len(),
                        "oversized input from client, closing"
                    );
                    let _ = server_event_tx
                        .blocking_send(ServerEvent::ClientDisconnected { client_id });
                    break;
                } else {
                    ServerEvent::ClientInput { client_id, data }
                }
            }
            ClientMessage::InputEvents { events } => {
                if !input_events_within_limits(&events) {
                    warn!(
                        client_id,
                        count = events.len(),
                        "oversized input events from client, closing"
                    );
                    let _ = server_event_tx
                        .blocking_send(ServerEvent::ClientDisconnected { client_id });
                    break;
                } else {
                    ServerEvent::ClientInputEvents { client_id, events }
                }
            }
            ClientMessage::ObserveTerminal { target } => {
                ServerEvent::ClientObserveTerminal { client_id, target }
            }
            ClientMessage::ControlTerminal { target, takeover } => {
                ServerEvent::ClientControlTerminal {
                    client_id,
                    target,
                    takeover,
                }
            }
            ClientMessage::ClipboardImage { extension, data } => {
                if data.len() > MAX_CLIPBOARD_IMAGE_PAYLOAD {
                    warn!(
                        client_id,
                        size = data.len(),
                        "oversized clipboard image from client, closing"
                    );
                    let _ = server_event_tx
                        .blocking_send(ServerEvent::ClientDisconnected { client_id });
                    break;
                } else {
                    ServerEvent::ClientClipboardImage {
                        client_id,
                        extension,
                        data,
                    }
                }
            }
            ClientMessage::Resize {
                cols,
                rows,
                cell_width_px,
                cell_height_px,
            } => {
                let (clamped_cols, clamped_rows) = clamp_terminal_size(cols, rows);
                ServerEvent::ClientResize {
                    client_id,
                    cols: clamped_cols,
                    rows: clamped_rows,
                    cell_width_px,
                    cell_height_px,
                }
            }
            ClientMessage::Detach => ServerEvent::ClientDetach { client_id },
            ClientMessage::AttachTerminal {
                terminal_id,
                takeover,
            } => ServerEvent::ClientAttachTerminal {
                client_id,
                terminal_id,
                takeover,
            },
            ClientMessage::AttachScroll {
                source,
                direction,
                lines,
                column,
                row,
                modifiers,
            } => ServerEvent::ClientAttachScroll {
                client_id,
                source,
                direction,
                lines,
                column,
                row,
                modifiers,
            },
            ClientMessage::ExternalOpenPolicyUpdate { policy } => {
                ServerEvent::ExternalOpenPolicyUpdate { client_id, policy }
            }
            ClientMessage::ExternalOpenReady { request_id, target } => {
                ServerEvent::ExternalOpenReady {
                    client_id,
                    request_id,
                    target,
                }
            }
            ClientMessage::ExternalOpenPreparationFailed { request_id, reason } => {
                ServerEvent::ExternalOpenPreparationFailed {
                    client_id,
                    request_id,
                    reason,
                }
            }
            ClientMessage::ExternalOpenResult { request_id, result } => {
                ServerEvent::ExternalOpenResult {
                    client_id,
                    request_id,
                    result,
                }
            }
            ClientMessage::ExternalOpenPolicyMutationResult {
                request_id,
                requested_policy,
                persisted_policy,
                effective_policy,
                failure_stage,
            } => ServerEvent::ExternalOpenPolicyMutationResult {
                client_id,
                request_id,
                requested_policy,
                persisted_policy,
                effective_policy,
                failure_stage,
            },
            ClientMessage::ExternalOpenPolicyReloadFailed {
                effective_policy,
                cleanup_incomplete,
            } => ServerEvent::ExternalOpenPolicyReloadFailed {
                client_id,
                effective_policy,
                cleanup_incomplete,
            },
            ClientMessage::Hello { .. } => {
                // Duplicate Hello — ignore.
                continue;
            }
        };

        if server_event_tx.blocking_send(event).is_err() {
            break; // Main loop gone.
        }
    }

    debug!(client_id, "client read thread exiting");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::local_socket::traits::Listener as _;
    use std::path::PathBuf;

    struct TestSocketPath(PathBuf);

    impl Drop for TestSocketPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn unique_test_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let filename = format!("h{}-{nanos}.sock", std::process::id());
        #[cfg(unix)]
        {
            let _ = name;
            PathBuf::from("/tmp").join(filename)
        }
        #[cfg(windows)]
        {
            std::env::temp_dir().join(format!("herdr-{name}-{filename}"))
        }
    }

    fn local_stream_pair(name: &str) -> (LocalStream, LocalStream, TestSocketPath) {
        let path = unique_test_path(name);
        let _ = std::fs::remove_file(&path);
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let client = crate::ipc::connect_local_stream(&path).unwrap();
        let server = listener.accept().unwrap();
        (client, server, TestSocketPath(path))
    }

    fn test_queue_writer() -> (ClientWriter, Arc<ClientWriterQueue>) {
        let queue = ClientWriterQueue::new();
        (
            ClientWriter {
                control: ClientControlWriter::queue(queue.clone()),
                render: ClientRenderWriter::queue(queue.clone()),
            },
            queue,
        )
    }

    fn frame_server_message(message: &ServerMessage) -> Vec<u8> {
        let mut bytes = Vec::new();
        protocol::write_message(&mut bytes, message).expect("frame server message");
        bytes
    }

    fn test_frame_acknowledgement() -> crate::server::client_projection::ClientFrameAcknowledgement
    {
        let mut projections = crate::server::client_projection::ClientProjections::default();
        assert!(projections.connect(1, crate::protocol::ExternalOpenPolicy::Disabled));
        projections
            .prepare_frame_acknowledgement(1, Default::default())
            .expect("frame acknowledgement")
    }

    #[test]
    fn client_writer_queue_keeps_render_slot_bounded() {
        let (writer, _queue) = test_queue_writer();
        let first = frame_server_message(&ServerMessage::WindowTitle {
            title: Some("first".into()),
        });
        let second = frame_server_message(&ServerMessage::WindowTitle {
            title: Some("second".into()),
        });

        writer.render.try_send(first).expect("first render fits");
        assert!(matches!(
            writer.render.try_send(second),
            Err(TrySendError::Full(_))
        ));
    }

    #[test]
    fn client_writer_prioritizes_control_and_reports_render_drain() {
        let (mut client_stream, server_stream, _path) = local_stream_pair("client-writer-priority");
        let (writer, queue) = test_queue_writer();
        let acknowledgement = test_frame_acknowledgement();
        writer
            .render
            .try_send_with_write_notification(
                frame_server_message(&ServerMessage::WindowTitle {
                    title: Some("render".into()),
                }),
                acknowledgement.clone(),
            )
            .expect("queue render");
        writer
            .control
            .send(frame_server_message(&ServerMessage::ReloadClientConfig))
            .expect("queue control");

        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let handle = std::thread::spawn(move || {
            client_writer_loop(server_stream, 9, queue, server_event_tx);
        });

        match protocol::read_message(&mut client_stream, MAX_FRAME_SIZE).expect("read control") {
            ServerMessage::ReloadClientConfig => {}
            other => panic!("expected control message first, got {other:?}"),
        }
        match protocol::read_message(&mut client_stream, MAX_FRAME_SIZE).expect("read render") {
            ServerMessage::WindowTitle { title } => assert_eq!(title.as_deref(), Some("render")),
            other => panic!("expected render message second, got {other:?}"),
        }
        match server_event_rx
            .blocking_recv()
            .expect("writer drained render slot")
        {
            ServerEvent::ClientWriterDrained { client_id } => assert_eq!(client_id, 9),
            other => panic!("expected writer drained event, got {other:?}"),
        }
        match server_event_rx
            .blocking_recv()
            .expect("frame written event")
        {
            ServerEvent::ClientFrameWritten {
                client_id,
                acknowledgement: written,
            } => {
                assert_eq!(client_id, 9);
                assert_eq!(written, acknowledgement);
            }
            other => panic!("expected frame written event, got {other:?}"),
        }

        drop(writer);
        handle.join().expect("writer exits after senders drop");
    }

    #[test]
    fn client_writer_exits_when_all_writer_handles_drop() {
        let (_client_stream, server_stream, _path) = local_stream_pair("client-writer-drop");
        let (writer, queue) = test_queue_writer();
        let (server_event_tx, _server_event_rx) = mpsc::channel(4);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            client_writer_loop(server_stream, 11, queue, server_event_tx);
            let _ = done_tx.send(());
        });

        drop(writer);
        done_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("writer exits without polling after senders drop");
    }

    #[test]
    fn client_writer_clone_keeps_loop_alive_until_final_drop() {
        let (mut client_stream, server_stream, _path) =
            local_stream_pair("client-writer-clone-drop");
        let (writer, queue) = test_queue_writer();
        let cloned_writer = writer.clone();
        let (server_event_tx, _server_event_rx) = mpsc::channel(4);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            client_writer_loop(server_stream, 12, queue, server_event_tx);
            let _ = done_tx.send(());
        });

        drop(writer);
        cloned_writer
            .control
            .send(frame_server_message(&ServerMessage::ReloadClientConfig))
            .expect("cloned writer still sends after original drops");
        match protocol::read_message(&mut client_stream, MAX_FRAME_SIZE)
            .expect("read control from cloned writer")
        {
            ServerMessage::ReloadClientConfig => {}
            other => panic!("expected cloned control message, got {other:?}"),
        }
        assert!(
            done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "writer exited while cloned handles were still alive"
        );

        drop(cloned_writer);
        done_rx
            .recv_timeout(Duration::from_millis(100))
            .expect("writer exits after final cloned writer drops");
    }

    #[test]
    fn client_writer_closes_queue_after_socket_write_failure() {
        let (client_stream, server_stream, _path) =
            local_stream_pair("client-writer-socket-failure");
        #[cfg(not(windows))]
        server_stream
            .set_send_timeout(Some(Duration::from_millis(100)))
            .expect("set test send timeout");
        let (writer, queue) = test_queue_writer();
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            client_writer_loop(server_stream, 13, queue, server_event_tx);
            let _ = done_tx.send(());
        });

        drop(client_stream);
        writer
            .control
            .send(vec![b'x'; 1024 * 1024])
            .expect("message is accepted before the writer observes socket failure");
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer exits after socket write failure");
        assert!(matches!(
            server_event_rx.blocking_recv(),
            Some(ServerEvent::ClientWriterFailed { client_id: 13 })
        ));

        assert!(matches!(writer.control.send(vec![b'y']), Err(SendError(_))));
        assert!(matches!(
            writer.render.try_send(vec![b'z']),
            Err(TrySendError::Disconnected(_))
        ));
    }

    #[test]
    fn failed_render_write_emits_no_frame_acknowledgement() {
        let (client_stream, server_stream, _path) =
            local_stream_pair("client-render-ack-socket-failure");
        drop(client_stream);
        let (writer, queue) = test_queue_writer();
        let acknowledgement = test_frame_acknowledgement();
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let handle = std::thread::spawn(move || {
            client_writer_loop(server_stream, 14, queue, server_event_tx);
        });

        writer
            .render
            .try_send_with_write_notification(vec![b'x'; 1024 * 1024], acknowledgement)
            .expect("render is accepted before the writer observes socket failure");
        handle.join().expect("writer exits after render failure");

        let mut drained = false;
        let mut failed = false;
        while let Some(event) = server_event_rx.blocking_recv() {
            match event {
                ServerEvent::ClientWriterDrained { client_id: 14 } => drained = true,
                ServerEvent::ClientWriterFailed { client_id: 14 } => failed = true,
                ServerEvent::ClientFrameWritten { .. } => {
                    panic!("failed socket write must not acknowledge its frame")
                }
                other => panic!("unexpected writer event: {other:?}"),
            }
        }
        assert!(drained);
        assert!(failed);
    }

    #[test]
    fn clamp_terminal_size_zero_zero() {
        assert_eq!(
            clamp_terminal_size(0, 0),
            (MIN_CLIENT_COLS, MIN_CLIENT_ROWS)
        );
    }

    #[test]
    fn clamp_terminal_size_one_one() {
        assert_eq!(clamp_terminal_size(1, 1), (1, 1));
    }

    #[test]
    fn clamp_terminal_size_preserves_narrow_client_size() {
        assert_eq!(clamp_terminal_size(40, 12), (40, 12));
    }

    #[test]
    fn clamp_terminal_size_valid() {
        assert_eq!(clamp_terminal_size(120, 40), (120, 40));
    }

    #[test]
    fn clamp_terminal_size_exact_minimum() {
        assert_eq!(
            clamp_terminal_size(MIN_CLIENT_COLS, MIN_CLIENT_ROWS),
            (MIN_CLIENT_COLS, MIN_CLIENT_ROWS)
        );
    }

    #[test]
    fn parse_client_keybindings_accepts_local_profile() {
        let keybindings = parse_client_keybindings(ClientKeybindings::Local {
            keys_toml: r#"
[keys]
prefix = "ctrl+a"
new_tab = "prefix+t"

[[keys.command]]
key = "prefix+g"
command = "lazygit"
"#
            .to_owned(),
        })
        .expect("valid client keybindings")
        .expect("local profile");

        assert_eq!(keybindings.prefix.0, crossterm::event::KeyCode::Char('a'));
        assert!(keybindings
            .keybinds
            .new_tab
            .bindings
            .iter()
            .any(|binding| binding.label == "prefix+t"));
        assert!(keybindings.keybinds.custom_commands.is_empty());
    }

    #[test]
    fn parse_client_keybindings_tolerates_disabled_bindings() {
        let keybindings = parse_client_keybindings(ClientKeybindings::Local {
            keys_toml: r#"
[keys]
new_tab = "ctrl+notakey"
"#
            .to_owned(),
        })
        .expect("diagnostic-only client keybindings should be accepted")
        .expect("local profile");

        assert!(keybindings.keybinds.new_tab.bindings.is_empty());
        assert!(keybindings
            .keybinds
            .next_tab
            .bindings
            .iter()
            .any(|binding| binding.label == "prefix+n"));
    }

    #[test]
    fn handshake_negotiates_terminal_ansi_encoding() {
        let (mut client_stream, server_stream, _path) = local_stream_pair("client-handshake-ansi");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let handshake_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            handle_client_handshake(server_stream, 42, &server_event_tx, &handshake_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::Hello {
                version: PROTOCOL_VERSION,
                cols: 100,
                rows: 30,
                cell_width_px: 8,
                cell_height_px: 16,
                requested_encoding: RenderEncoding::TerminalAnsi,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::App,
                external_open_policy: Some(crate::protocol::ExternalOpenPolicy::Disabled),
                external_open_attachment_id: Some(
                    crate::protocol::ExternalOpenAttachmentId::for_test(1),
                ),
            },
        )
        .expect("write hello");

        let welcome: ServerMessage =
            protocol::read_message(&mut client_stream, MAX_FRAME_SIZE).expect("read welcome");
        match welcome {
            ServerMessage::Welcome {
                version,
                encoding,
                error,
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(encoding, RenderEncoding::TerminalAnsi);
                assert_eq!(error, None);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }

        match server_event_rx
            .blocking_recv()
            .expect("client connected event")
        {
            ServerEvent::ClientConnected {
                client_id,
                cols,
                rows,
                cell_width_px,
                cell_height_px,
                render_encoding,
                keybindings,
                direct_attach_requested,
                external_open_policy,
                external_open_attachment_id,
                writer,
            } => {
                assert_eq!(client_id, 42);
                assert_eq!((cols, rows), (100, 30));
                assert_eq!((cell_width_px, cell_height_px), (8, 16));
                assert_eq!(render_encoding, RenderEncoding::TerminalAnsi);
                assert!(keybindings.is_none());
                assert!(!direct_attach_requested);
                assert_eq!(
                    external_open_policy,
                    Some(crate::protocol::ExternalOpenPolicy::Disabled)
                );
                assert_eq!(
                    external_open_attachment_id,
                    Some(crate::protocol::ExternalOpenAttachmentId::for_test(1))
                );
                drop(writer);
            }
            other => panic!("expected ClientConnected, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("handshake thread join")
            .expect("handshake thread result");
    }

    #[test]
    fn handshake_marks_terminal_attach_launch_mode() {
        let (mut client_stream, server_stream, _path) =
            local_stream_pair("client-handshake-terminal-attach");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let handshake_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            handle_client_handshake(server_stream, 42, &server_event_tx, &handshake_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::Hello {
                version: PROTOCOL_VERSION,
                cols: 100,
                rows: 30,
                cell_width_px: 8,
                cell_height_px: 16,
                requested_encoding: RenderEncoding::TerminalAnsi,
                keybindings: ClientKeybindings::Server,
                launch_mode: ClientLaunchMode::TerminalAttach,
                external_open_policy: None,
                external_open_attachment_id: None,
            },
        )
        .expect("write hello");

        let welcome: ServerMessage =
            protocol::read_message(&mut client_stream, MAX_FRAME_SIZE).expect("read welcome");
        match welcome {
            ServerMessage::Welcome {
                version,
                encoding,
                error,
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(encoding, RenderEncoding::TerminalAnsi);
                assert_eq!(error, None);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }

        match server_event_rx
            .blocking_recv()
            .expect("client connected event")
        {
            ServerEvent::ClientConnected {
                direct_attach_requested,
                external_open_policy,
                writer,
                ..
            } => {
                assert!(direct_attach_requested);
                assert_eq!(external_open_policy, None);
                drop(writer);
            }
            other => panic!("expected ClientConnected, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("handshake thread join")
            .expect("handshake thread result");
    }

    #[test]
    fn handshake_rejects_policy_presence_for_the_wrong_connection_kind() {
        for (
            name,
            launch_mode,
            external_open_policy,
            external_open_attachment_id,
            expected_error,
        ) in [
            (
                "app-missing-policy",
                ClientLaunchMode::App,
                None,
                Some(crate::protocol::ExternalOpenAttachmentId::for_test(1)),
                "full app client must advertise external-open policy",
            ),
            (
                "app-missing-attachment",
                ClientLaunchMode::App,
                Some(crate::protocol::ExternalOpenPolicy::Enabled),
                None,
                "full app client must advertise external-open attachment identity",
            ),
            (
                "terminal-advertises-policy",
                ClientLaunchMode::TerminalAttach,
                Some(crate::protocol::ExternalOpenPolicy::Enabled),
                Some(crate::protocol::ExternalOpenAttachmentId::for_test(1)),
                "terminal connection must not advertise external-open policy",
            ),
            (
                "terminal-spoofs-attachment",
                ClientLaunchMode::TerminalAttach,
                None,
                Some(crate::protocol::ExternalOpenAttachmentId::for_test(1)),
                "terminal connection must not advertise external-open policy",
            ),
        ] {
            let (mut client_stream, server_stream, _path) = local_stream_pair(name);
            let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
            let should_quit = Arc::new(AtomicBool::new(false));
            let handshake_quit = should_quit.clone();
            let handle = std::thread::spawn(move || {
                handle_client_handshake(server_stream, 42, &server_event_tx, &handshake_quit)
            });
            protocol::write_message(
                &mut client_stream,
                &ClientMessage::Hello {
                    version: PROTOCOL_VERSION,
                    cols: 80,
                    rows: 24,
                    cell_width_px: 0,
                    cell_height_px: 0,
                    requested_encoding: RenderEncoding::SemanticFrame,
                    keybindings: ClientKeybindings::Server,
                    launch_mode,
                    external_open_policy,
                    external_open_attachment_id,
                },
            )
            .expect("write invalid hello");

            let welcome: ServerMessage =
                protocol::read_message(&mut client_stream, MAX_FRAME_SIZE).expect("read rejection");
            assert!(matches!(
                welcome,
                ServerMessage::Welcome { error: Some(error), .. } if error == expected_error
            ));
            assert!(server_event_rx.try_recv().is_err());
            drop(client_stream);
            should_quit.store(true, Ordering::Release);
            handle
                .join()
                .expect("handshake thread join")
                .expect("handshake result");
        }
    }

    #[test]
    fn client_read_loop_rejects_oversized_input() {
        let (mut client_stream, server_stream, _path) = local_stream_pair("client-read-oversized");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let read_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            client_read_loop(server_stream, 7, &server_event_tx, &read_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::Input {
                data: vec![b'x'; MAX_INPUT_PAYLOAD + 1],
            },
        )
        .expect("write oversized input");

        match server_event_rx
            .blocking_recv()
            .expect("client disconnected event")
        {
            ServerEvent::ClientDisconnected { client_id } => assert_eq!(client_id, 7),
            other => panic!("expected ClientDisconnected, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("read thread join")
            .expect("read thread result");
    }

    #[test]
    fn client_read_loop_forwards_input_events() {
        let (mut client_stream, server_stream, _path) = local_stream_pair("client-read-events");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let read_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            client_read_loop(server_stream, 7, &server_event_tx, &read_quit)
        });
        let events = vec![
            ClientInputEvent::Key {
                code: crate::protocol::ClientKeyCode::Enter,
                modifiers: 0,
                kind: crate::protocol::ClientKeyKind::Press,
            },
            ClientInputEvent::FocusGained,
        ];

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::InputEvents {
                events: events.clone(),
            },
        )
        .expect("write input events");

        match server_event_rx
            .blocking_recv()
            .expect("client input events event")
        {
            ServerEvent::ClientInputEvents {
                client_id,
                events: actual,
            } => {
                assert_eq!(client_id, 7);
                assert_eq!(actual, events);
            }
            other => panic!("expected ClientInputEvents, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("read thread join")
            .expect("read thread result");
    }

    #[test]
    fn client_socket_forwards_complete_policy_mutation_result_with_source_identity() {
        let (mut client_stream, server_stream, _path) =
            local_stream_pair("client-policy-mutation-result");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let read_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            client_read_loop(server_stream, 7, &server_event_tx, &read_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::ExternalOpenPolicyMutationResult {
                request_id: 41,
                requested_policy: crate::protocol::ExternalOpenPolicy::Enabled,
                persisted_policy: Some(crate::protocol::ExternalOpenPolicy::Enabled),
                effective_policy: crate::protocol::ExternalOpenPolicy::Disabled,
                failure_stage: Some(
                    crate::protocol::ExternalOpenPolicyMutationFailureStage::Reload,
                ),
            },
        )
        .expect("write policy mutation result");

        match server_event_rx
            .blocking_recv()
            .expect("policy mutation result event")
        {
            ServerEvent::ExternalOpenPolicyMutationResult {
                client_id,
                request_id,
                requested_policy,
                persisted_policy,
                effective_policy,
                failure_stage,
            } => {
                assert_eq!(client_id, 7);
                assert_eq!(request_id, 41);
                assert_eq!(
                    requested_policy,
                    crate::protocol::ExternalOpenPolicy::Enabled
                );
                assert_eq!(
                    persisted_policy,
                    Some(crate::protocol::ExternalOpenPolicy::Enabled)
                );
                assert_eq!(
                    effective_policy,
                    crate::protocol::ExternalOpenPolicy::Disabled
                );
                assert_eq!(
                    failure_stage,
                    Some(crate::protocol::ExternalOpenPolicyMutationFailureStage::Reload)
                );
            }
            other => panic!("expected policy mutation result, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("read thread join")
            .expect("read thread result");
    }

    #[test]
    fn client_read_loop_rejects_oversized_input_event_batch() {
        let (mut client_stream, server_stream, _path) =
            local_stream_pair("client-read-oversized-events");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let read_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            client_read_loop(server_stream, 7, &server_event_tx, &read_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::InputEvents {
                events: vec![ClientInputEvent::FocusGained; MAX_INPUT_EVENT_BATCH + 1],
            },
        )
        .expect("write oversized input events");

        match server_event_rx
            .blocking_recv()
            .expect("client disconnected event")
        {
            ServerEvent::ClientDisconnected { client_id } => assert_eq!(client_id, 7),
            other => panic!("expected ClientDisconnected, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("read thread join")
            .expect("read thread result");
    }

    #[test]
    fn client_read_loop_rejects_oversized_input_event_paste() {
        let (mut client_stream, server_stream, _path) =
            local_stream_pair("client-read-oversized-paste");
        let (server_event_tx, mut server_event_rx) = mpsc::channel(4);
        let should_quit = Arc::new(AtomicBool::new(false));
        let read_quit = should_quit.clone();
        let handle = std::thread::spawn(move || {
            client_read_loop(server_stream, 7, &server_event_tx, &read_quit)
        });

        protocol::write_message(
            &mut client_stream,
            &ClientMessage::InputEvents {
                events: vec![ClientInputEvent::Paste {
                    text: "x".repeat(MAX_INPUT_PAYLOAD + 1),
                }],
            },
        )
        .expect("write oversized paste event");

        match server_event_rx
            .blocking_recv()
            .expect("client disconnected event")
        {
            ServerEvent::ClientDisconnected { client_id } => assert_eq!(client_id, 7),
            other => panic!("expected ClientDisconnected, got {other:?}"),
        }

        drop(client_stream);
        should_quit.store(true, Ordering::Release);
        handle
            .join()
            .expect("read thread join")
            .expect("read thread result");
    }

    #[test]
    fn handshake_timeout_is_within_five_second_deadline() {
        // The handshake timeout must be short enough that
        // the connection is guaranteed to close within 5 seconds even with
        // OS overhead (thread scheduling, timer slack, cleanup).
        assert!(
            HANDSHAKE_TIMEOUT < Duration::from_secs(5),
            "HANDSHAKE_TIMEOUT ({:?}) must be less than 5 seconds to guarantee \
             connection close within the 5-second deadline",
            HANDSHAKE_TIMEOUT
        );
    }
}
