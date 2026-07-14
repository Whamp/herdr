use std::ffi::{CStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::external_open::{
    ForwardingController, ForwardingPolicyChange, ForwardingPreparation,
    ForwardingPreparationError, LoopbackTarget,
};

use super::broker::{BrokerServer, ForwardingClient};
use super::controller::NumericForwardingController;
use super::protocol::{CorrelationId, ForwardSpec, LoopbackAddress};
use super::worker::{
    CommandRunner, ControlAuthority, ControlInvocation, ControlOperation, ControlResult,
    ControlWorker, ProcessCommandRunner, WorkerJob, WorkerResult,
};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const ORPHAN_ROLE_ENV: &str = "HERDR_OPENSSH_ORPHAN_ROLE";
const ORPHAN_TEST_NAME: &str = "remote::forwarding::openssh_harness::abnormal_launcher_idle_expiry_and_reattachment_preserve_ownership";
const NORMAL_ROLE_ENV: &str = "HERDR_OPENSSH_NORMAL_ROLE";
const NORMAL_TEST_NAME: &str = "remote::forwarding::openssh_harness::normal_launcher_teardown_removes_master_socket_and_listener_immediately";
const NORMAL_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[test]
fn master_invocation_is_closed_structured_and_exact() {
    let ssh = Path::new("/private/bin/ssh");
    let config = Path::new("/private/empty_config");
    let control = Path::new("/private/control.sock");
    let identity = Path::new("/private/client_ed25519");
    let known_hosts = Path::new("/private/known_hosts");
    let target = "tester@herdr-openssh-harness";

    let foreground = MasterInvocation::new(
        ssh,
        config,
        control,
        identity,
        known_hosts,
        target,
        43_221,
        false,
    );
    let background = MasterInvocation::new(
        ssh,
        config,
        control,
        identity,
        known_hosts,
        target,
        43_221,
        true,
    );
    let expected = [
        "-F",
        "/private/empty_config",
        "-S",
        "/private/control.sock",
        "-M",
        "-N",
        "-p",
        "43221",
        "-i",
        "/private/client_ed25519",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=/private/known_hosts",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "HostKeyAlias=herdr-openssh-harness",
        "-o",
        "HostName=127.0.0.1",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "ControlPersist=60",
        target,
    ]
    .map(OsString::from)
    .to_vec();

    assert_eq!(foreground.executable, PathBuf::from("/private/bin/ssh"));
    assert_eq!(foreground.argv, expected);
    assert_eq!(foreground.stdio, MasterStdio::Null);
    let mut expected_background = foreground.argv.clone();
    expected_background.insert(6, OsString::from("-f"));
    assert_eq!(background.executable, foreground.executable);
    assert_eq!(background.argv, expected_background);
    assert_eq!(background.stdio, MasterStdio::Null);
    assert_eq!(
        foreground
            .argv
            .iter()
            .filter(|argument| argument.as_os_str() == "ControlPersist=60")
            .count(),
        1
    );
    assert!(!foreground.argv.iter().any(|argument| argument == "-L"));
    assert_eq!(
        foreground
            .argv
            .iter()
            .filter(|argument| argument.as_os_str() == target)
            .count(),
        1
    );
}

#[test]
fn real_openssh_scalar_listener_uses_the_exact_loopback_identity() {
    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    let address = representative_ipv4();
    let remote_port = reserve_port(IpAddr::V4(address)).expect("reserve remote port");
    let local_port = reserve_port(IpAddr::V4(address)).expect("reserve local port");
    assert_ne!(local_port, remote_port);
    let destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), remote_port))
        .expect("start remote destination");
    let runner = Arc::new(AuditedProcessRunner::default());
    let worker = ControlWorker::start(harness.authority(), runner.clone(), PROCESS_TIMEOUT);
    let specification = ForwardSpec {
        local_address: LoopbackAddress::Ipv4(address.octets()),
        local_port,
        remote_address: LoopbackAddress::Ipv4(address.octets()),
        remote_port,
    };

    submit_and_receive(&worker, 1, ControlOperation::Forward(specification))
        .expect("forward result")
        .assert_result(ControlResult::Succeeded);
    wait_for_connectable(SocketAddr::new(IpAddr::V4(address), local_port))
        .expect("exact listener ready");
    assert_not_connectable(SocketAddr::new(
        IpAddr::V4(negative_ipv4(address)),
        local_port,
    ));
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), local_port),
        b"scalar-open-ssh",
    );
    assert!(destination.accepted_connections() > 0);

    submit_and_receive(&worker, 2, ControlOperation::Cancel(specification))
        .expect("cancel result")
        .assert_result(ControlResult::Succeeded);
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), local_port))
        .expect("exact listener removed");

    assert_eq!(
        runner.invocations(),
        vec![
            expected_control_invocation(&harness, "forward", specification),
            expected_control_invocation(&harness, "cancel", specification),
        ]
    );
    harness.exit_master().expect("exit managed master");
}

#[test]
fn real_openssh_exact_scalar_cancellation_preserves_an_independent_listener() {
    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    let address = representative_ipv4();
    let first_remote = reserve_port(IpAddr::V4(address)).expect("reserve first destination");
    let second_remote = reserve_port(IpAddr::V4(address)).expect("reserve second destination");
    let first_local = reserve_port(IpAddr::V4(address)).expect("reserve first listener");
    let second_local = reserve_port(IpAddr::V4(address)).expect("reserve second listener");
    let first_destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), first_remote))
        .expect("start first destination");
    let second_destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), second_remote))
        .expect("start second destination");
    let runner = Arc::new(AuditedProcessRunner::default());
    let worker = ControlWorker::start(harness.authority(), runner.clone(), PROCESS_TIMEOUT);
    let first = ForwardSpec {
        local_address: LoopbackAddress::Ipv4(address.octets()),
        local_port: first_local,
        remote_address: LoopbackAddress::Ipv4(address.octets()),
        remote_port: first_remote,
    };
    let second = ForwardSpec {
        local_address: LoopbackAddress::Ipv4(address.octets()),
        local_port: second_local,
        remote_address: LoopbackAddress::Ipv4(address.octets()),
        remote_port: second_remote,
    };

    submit_and_receive(&worker, 1, ControlOperation::Forward(first))
        .expect("first forward")
        .assert_result(ControlResult::Succeeded);
    submit_and_receive(&worker, 2, ControlOperation::Forward(second))
        .expect("second forward")
        .assert_result(ControlResult::Succeeded);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), first_local),
        b"independent-first",
    );
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), second_local),
        b"independent-second",
    );

    submit_and_receive(&worker, 3, ControlOperation::Cancel(first))
        .expect("first exact cancellation")
        .assert_result(ControlResult::Succeeded);
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), first_local))
        .expect("first listener removed");
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), second_local),
        b"independent-unaffected",
    );
    assert!(first_destination.accepted_connections() > 0);
    assert!(second_destination.accepted_connections() >= 2);
    submit_and_receive(&worker, 4, ControlOperation::Cancel(second))
        .expect("second exact cancellation")
        .assert_result(ControlResult::Succeeded);

    assert_eq!(
        runner.invocations(),
        vec![
            expected_control_invocation(&harness, "forward", first),
            expected_control_invocation(&harness, "forward", second),
            expected_control_invocation(&harness, "cancel", first),
            expected_control_invocation(&harness, "cancel", second),
        ]
    );
    harness.exit_master().expect("exit managed master");
}

#[test]
fn real_openssh_ipv6_and_atomic_localhost_creation_and_exact_cancellation() {
    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    let remote_port = reserve_port(IpAddr::V6(Ipv6Addr::LOCALHOST)).expect("reserve IPv6 remote");
    let local_port = reserve_port(IpAddr::V6(Ipv6Addr::LOCALHOST)).expect("reserve IPv6 local");
    assert_ne!(local_port, remote_port);
    let destination = EchoServer::start(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        remote_port,
    ))
    .expect("start IPv6 destination");
    let runner = Arc::new(AuditedProcessRunner::default());
    let worker = ControlWorker::start(harness.authority(), runner.clone(), PROCESS_TIMEOUT);
    let ipv6 = ForwardSpec {
        local_address: LoopbackAddress::Ipv6,
        local_port,
        remote_address: LoopbackAddress::Ipv6,
        remote_port,
    };

    submit_and_receive(&worker, 1, ControlOperation::Forward(ipv6))
        .expect("IPv6 forward")
        .assert_result(ControlResult::Succeeded);
    wait_for_connectable(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_port))
        .expect("IPv6 listener ready");
    assert_round_trip(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_port),
        b"ipv6-open-ssh",
    );
    assert!(destination.accepted_connections() > 0);
    submit_and_receive(&worker, 2, ControlOperation::Cancel(ipv6))
        .expect("IPv6 cancel")
        .assert_result(ControlResult::Succeeded);
    wait_for_not_connectable(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_port))
        .expect("IPv6 listener removed");

    let pair_port = reserve_dual_stack_port().expect("reserve localhost pair port");
    let pair = super::worker::LocalhostPairSpec::new(pair_port, pair_port).expect("valid pair");
    let (pair_ipv4, pair_ipv6) = localhost_specs(pair_port, pair_port);
    submit_and_receive(&worker, 3, ControlOperation::ForwardPair(pair))
        .expect("localhost forward")
        .assert_result(ControlResult::PairSucceeded);
    wait_for_connectable(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pair_port))
        .expect("localhost IPv4 listener ready without remote destination");
    wait_for_connectable(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), pair_port))
        .expect("localhost IPv6 listener ready without remote destination");
    submit_and_receive(&worker, 4, ControlOperation::CancelPair(pair))
        .expect("localhost cancel")
        .assert_result(ControlResult::PairCancellationSucceeded);
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pair_port))
        .expect("localhost IPv4 removed");
    wait_for_not_connectable(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), pair_port))
        .expect("localhost IPv6 removed");

    assert_eq!(
        runner.invocations(),
        vec![
            expected_control_invocation(&harness, "forward", ipv6),
            expected_control_invocation(&harness, "cancel", ipv6),
            expected_control_invocation(&harness, "forward", pair_ipv4),
            expected_control_invocation(&harness, "forward", pair_ipv6),
            expected_control_invocation(&harness, "cancel", pair_ipv4),
            expected_control_invocation(&harness, "cancel", pair_ipv6),
        ]
    );
    harness.exit_master().expect("exit managed master");
}

#[test]
fn production_controller_remaps_reuses_and_cancels_independent_real_listeners() {
    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    let production = ProductionController::start(&harness).expect("start production controller");
    let address = representative_ipv4();
    let scalar_remote = reserve_port(IpAddr::V4(address)).expect("reserve scalar destination");
    let scalar_destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), scalar_remote))
        .expect("start scalar destination");

    let scalar_local = production
        .prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(scalar_remote).expect("scalar remote port"),
        )
        .expect("prepare remapped scalar");
    assert_ne!(scalar_local.get(), scalar_remote);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), scalar_local.get()),
        b"controller-scalar",
    );
    assert!(scalar_destination.accepted_connections() > 0);
    assert_eq!(
        production
            .prepare(
                LoopbackTarget::Ipv4(address),
                NonZeroU16::new(scalar_remote).expect("scalar remote port"),
            )
            .expect("reuse scalar"),
        scalar_local
    );

    let independent_remote = reserve_port(IpAddr::V4(address)).expect("reserve independent port");
    let independent_destination =
        EchoServer::start(SocketAddr::new(IpAddr::V4(address), independent_remote))
            .expect("start independent destination");
    let independent_local = production
        .prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(independent_remote).expect("independent remote port"),
        )
        .expect("prepare independent mapping");
    assert_ne!(independent_local, scalar_local);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), independent_local.get()),
        b"controller-independent",
    );
    assert!(independent_destination.accepted_connections() > 0);

    let localhost_remote = reserve_dual_stack_port().expect("reserve localhost destination");
    let localhost_v4 = EchoServer::start(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        localhost_remote,
    ))
    .expect("start localhost IPv4 destination");
    let localhost_v6 = EchoServer::start(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        localhost_remote,
    ))
    .expect("start localhost IPv6 destination");
    let localhost_local = production
        .prepare(
            LoopbackTarget::Localhost,
            NonZeroU16::new(localhost_remote).expect("localhost remote port"),
        )
        .expect("prepare atomic localhost mapping");
    assert_ne!(localhost_local.get(), localhost_remote);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), localhost_local.get()),
        b"controller-localhost-v4",
    );
    assert_round_trip(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), localhost_local.get()),
        b"controller-localhost-v6",
    );
    assert!(localhost_v4.accepted_connections() > 0);
    assert!(localhost_v6.accepted_connections() > 0);

    production.disable().expect("disable production forwarding");
    for address in [
        SocketAddr::new(IpAddr::V4(address), scalar_local.get()),
        SocketAddr::new(IpAddr::V4(address), independent_local.get()),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), localhost_local.get()),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), localhost_local.get()),
    ] {
        wait_for_not_connectable(address).expect("owned listener removed by policy cancellation");
    }
    drop(production);
    harness.exit_master().expect("exit managed master");
}

#[test]
fn production_atomic_localhost_failure_rolls_back_and_quarantines_the_real_candidate() {
    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    let production = ProductionController::start(&harness).expect("start production controller");
    let preferred = reserve_dual_stack_port().expect("reserve atomic candidate");
    let blocker = TcpListener::bind((Ipv6Addr::LOCALHOST, preferred))
        .expect("occupy second localhost member");

    assert_eq!(
        production.prepare(
            LoopbackTarget::Localhost,
            NonZeroU16::new(preferred).expect("preferred port"),
        ),
        Err(ForwardingPreparationError::AtomicCreationFailed)
    );
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), preferred))
        .expect("rolled-back IPv4 member removed");
    drop(blocker);
    wait_for_not_connectable(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), preferred))
        .expect("failed IPv6 member absent after blocker removal");

    let destination =
        EchoServer::start(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), preferred))
            .expect("restart IPv6 destination on quarantined preferred port");
    let remapped = production
        .prepare(
            LoopbackTarget::Localhost,
            NonZeroU16::new(preferred).expect("preferred port"),
        )
        .expect("later localhost candidate progresses");
    assert_ne!(remapped.get(), preferred);
    wait_for_connectable(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        remapped.get(),
    ))
    .expect("later IPv4 member ready");
    assert_round_trip(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), remapped.get()),
        b"atomic-retry-v6",
    );
    assert!(destination.accepted_connections() > 0);

    production.disable().expect("cancel remapped pair");
    wait_for_not_connectable(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        remapped.get(),
    ))
    .expect("remapped IPv4 removed");
    wait_for_not_connectable(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        remapped.get(),
    ))
    .expect("remapped IPv6 removed");
    drop(production);
    harness.exit_master().expect("exit managed master");
}

#[test]
fn production_attachment_teardown_and_master_death_remove_owned_real_listeners() {
    let mut normal = OpenSshHarness::start().expect("start normal teardown harness");
    let normal_production =
        ProductionController::start(&normal).expect("start normal production controller");
    let address = representative_ipv4();
    let normal_remote = reserve_port(IpAddr::V4(address)).expect("reserve normal destination");
    let normal_destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), normal_remote))
        .expect("start normal destination");
    let normal_local = normal_production
        .prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(normal_remote).expect("normal remote port"),
        )
        .expect("prepare normal mapping");
    drop(normal_production);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), normal_local.get()),
        b"listener-survives-broker-drop",
    );
    assert!(normal_destination.accepted_connections() > 0);
    normal.exit_master().expect("normal one-shot master exit");
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), normal_local.get()))
        .expect("normal master exit removes listener");
    normal
        .exit_master()
        .expect("normal master exit is idempotent");

    let mut failed = OpenSshHarness::start().expect("start master death harness");
    let failed_production =
        ProductionController::start(&failed).expect("start failed production controller");
    let failed_remote = reserve_port(IpAddr::V4(address)).expect("reserve failed destination");
    let _failed_destination =
        EchoServer::start(SocketAddr::new(IpAddr::V4(address), failed_remote))
            .expect("start failed destination");
    let failed_local = failed_production
        .prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(failed_remote).expect("failed remote port"),
        )
        .expect("prepare failed mapping");
    failed.kill_master().expect("kill managed master");
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), failed_local.get()))
        .expect("master death removes listener");
    let distinct_remote = reserve_port(IpAddr::V4(address)).expect("reserve post-death target");
    assert_eq!(
        failed_production.prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(distinct_remote).expect("post-death remote port"),
        ),
        Err(ForwardingPreparationError::Unavailable)
    );
}

#[test]
fn normal_launcher_teardown_removes_master_socket_and_listener_immediately() {
    if std::env::var_os(NORMAL_ROLE_ENV).is_some() {
        run_normal_launcher_role().expect("run normal launcher role");
        return;
    }

    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    harness
        .exit_master()
        .expect("remove fixture bootstrap master");
    let address = representative_ipv4();
    let local_port = reserve_port(IpAddr::V4(address)).expect("reserve normal listener");
    let remote_port = reserve_port(IpAddr::V4(address)).expect("reserve normal destination");
    let _destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), remote_port))
        .expect("start normal destination");
    let control_path = harness.root.join("normal-control.sock");
    let ready_file = harness.root.join("normal-ready");
    let teardown_file = harness.root.join("normal-teardown");
    let audit_file = harness.root.join("normal-audit");
    let mut cleanup = ManagedControl::from_harness(&harness, control_path.clone());
    let mut launcher = spawn_normal_launcher(
        &harness,
        &control_path,
        &ready_file,
        &teardown_file,
        &audit_file,
        address,
        local_port,
        remote_port,
    )
    .expect("spawn normal launcher");

    wait_for_file(&ready_file, &mut launcher).expect("normal launcher readiness");
    let readiness = fs::read_to_string(&ready_file).expect("read normal readiness");
    let master_pid = parse_published_value(&readiness, "master_pid")
        .expect("published normal master pid") as u32;
    assert_eq!(
        parse_published_value(&readiness, "listener").expect("published normal listener"),
        u64::from(local_port)
    );
    assert!(
        control_path.exists(),
        "normal control socket was not published"
    );
    assert!(cleanup.control_check().expect("normal control check"));
    assert!(process_exists(master_pid), "normal master was not running");
    wait_for_connectable(SocketAddr::new(IpAddr::V4(address), local_port))
        .expect("normal listener ready");

    let teardown_started = Instant::now();
    fs::write(&teardown_file, b"exit\n").expect("request deterministic normal teardown");
    let status = wait_for_reaped_child(
        &mut launcher,
        NORMAL_TEARDOWN_TIMEOUT,
        "normal launcher teardown",
    )
    .expect("normal launcher exits cleanly");
    assert!(status.success(), "normal launcher failed: {status}");
    assert_normal_teardown_complete(
        &control_path,
        SocketAddr::new(IpAddr::V4(address), local_port),
        master_pid,
        teardown_started + NORMAL_TEARDOWN_TIMEOUT,
    )
    .expect("normal teardown removed all owned state");
    assert!(
        teardown_started.elapsed() < NORMAL_TEARDOWN_TIMEOUT,
        "normal teardown used the idle-expiry deadline"
    );
    let audit = fs::read_to_string(&audit_file).expect("read normal teardown audit");
    assert_eq!(
        parse_published_value(&audit, "exit_commands").expect("normal exit command audit"),
        1
    );
    assert_eq!(
        parse_published_value(&audit, "cancel_commands").expect("normal cancel command audit"),
        0
    );
    cleanup.disarm();
}

#[test]
fn abnormal_launcher_idle_expiry_and_reattachment_preserve_ownership() {
    if std::env::var_os(ORPHAN_ROLE_ENV).is_some() {
        run_orphan_launcher_role().expect("run orphan launcher role");
        return;
    }

    let mut harness = OpenSshHarness::start().expect("start isolated OpenSSH harness");
    harness
        .exit_master()
        .expect("remove fixture bootstrap master");
    let address = representative_ipv4();
    let preferred = reserve_port(IpAddr::V4(address)).expect("reserve foreign preferred port");
    let destination_port = reserve_port(IpAddr::V4(address)).expect("reserve foreign destination");
    assert_ne!(preferred, destination_port);
    let destination = EchoServer::start(SocketAddr::new(IpAddr::V4(address), destination_port))
        .expect("start foreign destination");
    let orphan_control = harness.root.join("orphan-control.sock");
    let ready_file = harness.root.join("orphan-ready");
    let mut orphan = ManagedControl::from_harness(&harness, orphan_control.clone());
    let mut launcher = spawn_orphan_launcher(
        &harness,
        &orphan_control,
        &ready_file,
        address,
        preferred,
        destination_port,
    )
    .expect("spawn abnormal launcher");
    let launcher_pid = launcher.id().expect("orphan launcher pid");
    wait_for_file(&ready_file, &mut launcher).expect("orphan launcher readiness");
    let published = fs::read_to_string(&ready_file).expect("read orphan readiness");
    assert_eq!(
        parse_published_value(&published, "launcher_pid").expect("published launcher pid"),
        u64::from(launcher_pid)
    );
    assert_eq!(
        parse_published_value(&published, "listener").expect("published listener"),
        u64::from(preferred)
    );
    let published_pid =
        parse_published_value(&published, "master_pid").expect("published master pid") as u32;
    assert_eq!(
        orphan.master_pid().expect("query orphan master pid"),
        published_pid
    );
    wait_for_connectable(SocketAddr::new(IpAddr::V4(address), preferred))
        .expect("foreign listener ready");
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), preferred),
        b"foreign-before-kill",
    );

    launcher.kill_and_reap().expect("kill and reap launcher");
    assert!(orphan.control_check().expect("orphan control check"));
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), preferred),
        b"foreign-after-kill",
    );

    let mut fresh = ManagedControl::from_harness(&harness, harness.root.join("fresh-control.sock"));
    fresh.start().expect("start fresh attachment master");
    let production = ProductionController::start_with_authority(fresh.authority())
        .expect("start fresh production controller");
    let remapped = production
        .prepare(
            LoopbackTarget::Ipv4(address),
            NonZeroU16::new(preferred).expect("foreign preferred port"),
        )
        .expect("fresh attachment remaps foreign collision");
    assert_ne!(remapped.get(), preferred);
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), remapped.get()),
        b"fresh-through-foreign",
    );
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), preferred),
        b"foreign-independent",
    );
    assert!(destination.accepted_connections() >= 4);

    production.disable().expect("clean fresh owned listener");
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), remapped.get()))
        .expect("fresh listener removed independently");
    assert_round_trip(
        SocketAddr::new(IpAddr::V4(address), preferred),
        b"foreign-survives-fresh-cleanup",
    );
    drop(production);
    fresh.exit().expect("exit fresh master");

    let idle_started = Instant::now();
    let minimum_idle = Duration::from_secs(55);
    while idle_started.elapsed() < minimum_idle {
        assert!(
            process_exists(published_pid),
            "orphan master expired before the finite idle period"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let expiry_deadline = idle_started + Duration::from_secs(75);
    while process_exists(published_pid) {
        assert!(
            Instant::now() < expiry_deadline,
            "orphan master exceeded the finite idle-period tolerance"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), preferred))
        .expect("orphan listener removed after idle expiry");
    let socket_deadline = Instant::now() + READINESS_TIMEOUT;
    while orphan_control.exists() {
        assert!(
            Instant::now() < socket_deadline,
            "orphan control socket remained after master expiry"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
    assert_process_gone(published_pid).expect("orphan master process gone");
    orphan.disarm();
}

struct ProductionController {
    controller: NumericForwardingController,
    _client: ForwardingClient,
    _broker: BrokerServer,
}

impl ProductionController {
    fn start(harness: &OpenSshHarness) -> io::Result<Self> {
        Self::start_with_authority(harness.authority())
    }

    fn start_with_authority(authority: ControlAuthority) -> io::Result<Self> {
        let (server_stream, client_stream) = UnixStream::pair()?;
        let broker = BrokerServer::start(
            server_stream,
            crate::platform::InheritedPeerIdentity::current_process(),
            authority,
        )?;
        let client = ForwardingClient::from_stream(
            client_stream,
            true,
            crate::config::SavedPortForwardLimit::DEFAULT,
            crate::platform::InheritedPeerIdentity::current_process(),
        )?;
        let controller = NumericForwardingController::new(client.clone());
        Ok(Self {
            controller,
            _client: client,
            _broker: broker,
        })
    }

    fn prepare(
        &self,
        target: LoopbackTarget,
        remote_port: NonZeroU16,
    ) -> Result<NonZeroU16, ForwardingPreparationError> {
        let operation = self.controller.begin_prepare_numeric(target, remote_port)?;
        wait_for_preparation(operation)
    }

    fn disable(&self) -> Result<(), ForwardingPreparationError> {
        let operation = self
            .controller
            .begin_set_enabled(false, crate::config::SavedPortForwardLimit::DEFAULT)?;
        let settlement = wait_for_policy(operation)?;
        assert!(!settlement.effective);
        settlement.result
    }
}

fn wait_for_preparation(
    mut operation: Box<dyn ForwardingPreparation>,
) -> Result<NonZeroU16, ForwardingPreparationError> {
    let deadline = Instant::now() + READINESS_TIMEOUT + PROCESS_TIMEOUT;
    loop {
        if let Some(result) = operation.poll() {
            return result;
        }
        assert!(Instant::now() < deadline, "forward preparation timed out");
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_policy(
    mut operation: Box<dyn ForwardingPolicyChange>,
) -> Result<crate::external_open::ForwardingPolicySettlement, ForwardingPreparationError> {
    let deadline = Instant::now() + READINESS_TIMEOUT + PROCESS_TIMEOUT;
    loop {
        if let Some(settlement) = operation.poll() {
            return Ok(settlement);
        }
        assert!(Instant::now() < deadline, "forward policy change timed out");
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[derive(Default)]
struct AuditedProcessRunner {
    inner: ProcessCommandRunner,
    invocations: Mutex<Vec<ControlInvocation>>,
}

impl AuditedProcessRunner {
    fn invocations(&self) -> Vec<ControlInvocation> {
        self.invocations
            .lock()
            .expect("invocation audit lock")
            .clone()
    }
}

impl CommandRunner for AuditedProcessRunner {
    fn run(&self, invocation: &ControlInvocation, timeout: Duration) -> ControlResult {
        self.invocations
            .lock()
            .expect("invocation audit lock")
            .push(invocation.clone());
        self.inner.run(invocation, timeout)
    }

    fn cancel(&self) {
        self.inner.cancel();
    }
}

trait WorkerResultAssertion {
    fn assert_result(self, expected: ControlResult);
}

impl WorkerResultAssertion for WorkerResult {
    fn assert_result(self, expected: ControlResult) {
        assert_eq!(self.result, expected);
    }
}

fn submit_and_receive(
    worker: &ControlWorker,
    id: u64,
    operation: ControlOperation,
) -> io::Result<WorkerResult> {
    worker.submit(WorkerJob {
        id: CorrelationId::new(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "zero correlation id"))?,
        operation,
    })?;
    let deadline = Instant::now() + READINESS_TIMEOUT + PROCESS_TIMEOUT;
    loop {
        match worker.try_recv() {
            Ok(result) => return Ok(result),
            Err(std::sync::mpsc::TryRecvError::Empty) if Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "OpenSSH control result timed out",
                ));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "OpenSSH control worker disconnected",
                ));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasterStdio {
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterInvocation {
    executable: PathBuf,
    argv: Vec<OsString>,
    stdio: MasterStdio,
}

impl MasterInvocation {
    // The closed invocation owns one token for every independently audited SSH input.
    #[allow(clippy::too_many_arguments)]
    fn new(
        executable: &Path,
        config: &Path,
        control: &Path,
        identity: &Path,
        known_hosts: &Path,
        target: &str,
        server_port: u16,
        background: bool,
    ) -> Self {
        let mut argv = vec![
            OsString::from("-F"),
            config.as_os_str().to_owned(),
            OsString::from("-S"),
            control.as_os_str().to_owned(),
            OsString::from("-M"),
            OsString::from("-N"),
        ];
        if background {
            argv.push(OsString::from("-f"));
        }
        argv.extend([
            OsString::from("-p"),
            OsString::from(server_port.to_string()),
            OsString::from("-i"),
            identity.as_os_str().to_owned(),
            OsString::from("-o"),
            OsString::from("BatchMode=yes"),
            OsString::from("-o"),
            OsString::from("IdentitiesOnly=yes"),
            OsString::from("-o"),
            OsString::from("IdentityAgent=none"),
            OsString::from("-o"),
            OsString::from("StrictHostKeyChecking=yes"),
            OsString::from("-o"),
            OsString::from(format!("UserKnownHostsFile={}", known_hosts.display())),
            OsString::from("-o"),
            OsString::from("GlobalKnownHostsFile=/dev/null"),
            OsString::from("-o"),
            OsString::from("HostKeyAlias=herdr-openssh-harness"),
            OsString::from("-o"),
            OsString::from("HostName=127.0.0.1"),
            OsString::from("-o"),
            OsString::from("ProxyCommand=none"),
            OsString::from("-o"),
            OsString::from("ProxyJump=none"),
            OsString::from("-o"),
            OsString::from("ForwardAgent=no"),
            OsString::from("-o"),
            OsString::from("ClearAllForwardings=yes"),
            OsString::from("-o"),
            OsString::from("PermitLocalCommand=no"),
            OsString::from("-o"),
            OsString::from("RequestTTY=no"),
            OsString::from("-o"),
            OsString::from("ControlPersist=60"),
            OsString::from(target),
        ]);
        Self {
            executable: executable.to_path_buf(),
            argv,
            stdio: MasterStdio::Null,
        }
    }

    fn spawn(&self) -> io::Result<Child> {
        let mut command = isolated_command(&self.executable);
        command.args(&self.argv);
        match self.stdio {
            MasterStdio::Null => {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
            }
        }
        command.spawn()
    }
}

struct ManagedControl {
    ssh: PathBuf,
    config: PathBuf,
    control: PathBuf,
    identity: PathBuf,
    known_hosts: PathBuf,
    target: String,
    server_port: u16,
    cleanup: bool,
    exit_commands: usize,
}

impl ManagedControl {
    fn from_harness(harness: &OpenSshHarness, control: PathBuf) -> Self {
        Self {
            ssh: harness.ssh.clone(),
            config: harness.config.clone(),
            control,
            identity: harness.identity.clone(),
            known_hosts: harness.known_hosts.clone(),
            target: harness.target.clone(),
            server_port: harness.server_port,
            cleanup: true,
            exit_commands: 0,
        }
    }

    fn from_role_environment() -> io::Result<Self> {
        Ok(Self {
            ssh: role_path("HERDR_OPENSSH_SSH")?,
            config: role_path("HERDR_OPENSSH_CONFIG")?,
            control: role_path("HERDR_OPENSSH_CONTROL")?,
            identity: role_path("HERDR_OPENSSH_IDENTITY")?,
            known_hosts: role_path("HERDR_OPENSSH_KNOWN_HOSTS")?,
            target: role_string("HERDR_OPENSSH_TARGET")?,
            server_port: role_u16("HERDR_OPENSSH_SERVER_PORT")?,
            cleanup: true,
            exit_commands: 0,
        })
    }

    fn authority(&self) -> ControlAuthority {
        ControlAuthority::new(self.target.clone(), self.control.clone())
    }

    fn start(&self) -> io::Result<()> {
        let mut child = self.master_invocation().spawn()?;
        let deadline = Instant::now() + READINESS_TIMEOUT;
        loop {
            if self.control_check()? {
                let _ = child.try_wait()?;
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "managed OpenSSH attachment exited before readiness ({status})"
                    )));
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed OpenSSH attachment did not become ready",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn master_invocation(&self) -> MasterInvocation {
        MasterInvocation::new(
            &self.ssh,
            &self.config,
            &self.control,
            &self.identity,
            &self.known_hosts,
            &self.target,
            self.server_port,
            true,
        )
    }

    fn control_command(&self, operation: &str) -> Command {
        let mut command = isolated_command(&self.ssh);
        command
            .arg("-F")
            .arg(&self.config)
            .arg("-S")
            .arg(&self.control)
            .arg("-O")
            .arg(operation)
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg(&self.target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn control_check(&self) -> io::Result<bool> {
        wait_bounded(
            &mut self.control_command("check"),
            PROCESS_TIMEOUT,
            "managed attachment control check",
        )
        .map(|status| status.success())
    }

    fn master_pid(&self) -> io::Result<u32> {
        let mut command = self.control_command("check");
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let status = wait_for_child(&mut child, PROCESS_TIMEOUT, "managed attachment pid check")?;
        let mut output = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut output)?;
        }
        if !status.success() {
            return Err(io::Error::other("managed attachment is not running"));
        }
        parse_control_pid(&output)
    }

    fn exit(&mut self) -> io::Result<()> {
        if !self.control.exists() {
            self.cleanup = false;
            return Ok(());
        }
        self.exit_commands += 1;
        let status = wait_bounded(
            &mut self.control_command("exit"),
            PROCESS_TIMEOUT,
            "managed attachment exit",
        )?;
        if !status.success() {
            return Err(io::Error::other("managed attachment exit failed"));
        }
        let deadline = Instant::now() + READINESS_TIMEOUT;
        while self.control.exists() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed attachment control socket remained after exit",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        self.cleanup = false;
        Ok(())
    }

    fn exit_command_count(&self) -> usize {
        self.exit_commands
    }

    fn disarm(&mut self) {
        self.cleanup = false;
    }
}

impl Drop for ManagedControl {
    fn drop(&mut self) {
        if self.cleanup && self.control.exists() {
            let _ = wait_bounded(
                &mut self.control_command("exit"),
                Duration::from_secs(2),
                "managed attachment cleanup",
            );
        }
    }
}

struct ReapedChild(Option<Child>);

impl ReapedChild {
    fn id(&self) -> Option<u32> {
        self.0.as_ref().map(Child::id)
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.0.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(None),
        }
    }

    fn kill_and_reap(&mut self) -> io::Result<()> {
        let Some(mut child) = self.0.take() else {
            return Ok(());
        };
        child.kill()?;
        child.wait()?;
        Ok(())
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_normal_launcher(
    harness: &OpenSshHarness,
    control: &Path,
    ready_file: &Path,
    teardown_file: &Path,
    audit_file: &Path,
    address: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
) -> io::Result<ReapedChild> {
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(NORMAL_TEST_NAME)
        .arg("--test-threads=1")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env(NORMAL_ROLE_ENV, "1")
        .env("HERDR_OPENSSH_SSH", &harness.ssh)
        .env("HERDR_OPENSSH_CONFIG", &harness.config)
        .env("HERDR_OPENSSH_CONTROL", control)
        .env("HERDR_OPENSSH_IDENTITY", &harness.identity)
        .env("HERDR_OPENSSH_KNOWN_HOSTS", &harness.known_hosts)
        .env("HERDR_OPENSSH_TARGET", &harness.target)
        .env("HERDR_OPENSSH_SERVER_PORT", harness.server_port.to_string())
        .env("HERDR_OPENSSH_READY", ready_file)
        .env("HERDR_OPENSSH_TEARDOWN", teardown_file)
        .env("HERDR_OPENSSH_AUDIT", audit_file)
        .env("HERDR_OPENSSH_ADDRESS", address.to_string())
        .env("HERDR_OPENSSH_LOCAL_PORT", local_port.to_string())
        .env("HERDR_OPENSSH_REMOTE_PORT", remote_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().map(|child| ReapedChild(Some(child)))
}

fn spawn_orphan_launcher(
    harness: &OpenSshHarness,
    control: &Path,
    ready_file: &Path,
    address: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
) -> io::Result<ReapedChild> {
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(ORPHAN_TEST_NAME)
        .arg("--test-threads=1")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env(ORPHAN_ROLE_ENV, "1")
        .env("HERDR_OPENSSH_SSH", &harness.ssh)
        .env("HERDR_OPENSSH_CONFIG", &harness.config)
        .env("HERDR_OPENSSH_CONTROL", control)
        .env("HERDR_OPENSSH_IDENTITY", &harness.identity)
        .env("HERDR_OPENSSH_KNOWN_HOSTS", &harness.known_hosts)
        .env("HERDR_OPENSSH_TARGET", &harness.target)
        .env("HERDR_OPENSSH_SERVER_PORT", harness.server_port.to_string())
        .env("HERDR_OPENSSH_READY", ready_file)
        .env("HERDR_OPENSSH_ADDRESS", address.to_string())
        .env("HERDR_OPENSSH_LOCAL_PORT", local_port.to_string())
        .env("HERDR_OPENSSH_REMOTE_PORT", remote_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().map(|child| ReapedChild(Some(child)))
}

fn run_normal_launcher_role() -> io::Result<()> {
    let mut control = ManagedControl::from_role_environment()?;
    control.start()?;
    let address = role_string("HERDR_OPENSSH_ADDRESS")?
        .parse::<Ipv4Addr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid role address"))?;
    let local_port = role_u16("HERDR_OPENSSH_LOCAL_PORT")?;
    let remote_port = role_u16("HERDR_OPENSSH_REMOTE_PORT")?;
    let runner = Arc::new(AuditedProcessRunner::default());
    let worker = ControlWorker::start(control.authority(), runner.clone(), PROCESS_TIMEOUT);
    let specification = ForwardSpec {
        local_address: LoopbackAddress::Ipv4(address.octets()),
        local_port,
        remote_address: LoopbackAddress::Ipv4(address.octets()),
        remote_port,
    };
    let result = submit_and_receive(&worker, 1, ControlOperation::Forward(specification))?;
    if result.result != ControlResult::Succeeded {
        return Err(io::Error::other(
            "normal role could not create its listener",
        ));
    }
    wait_for_connectable(SocketAddr::new(IpAddr::V4(address), local_port))?;
    let ready_file = role_path("HERDR_OPENSSH_READY")?;
    fs::write(
        ready_file,
        format!(
            "launcher_pid={}\nmaster_pid={}\nlistener={}\ncontrol_ready=1\n",
            std::process::id(),
            control.master_pid()?,
            local_port,
        ),
    )?;

    let teardown_file = role_path("HERDR_OPENSSH_TEARDOWN")?;
    wait_for_teardown_command(&teardown_file)?;
    control.exit()?;
    control.exit()?;
    if control.exit_command_count() != 1 {
        return Err(io::Error::other(
            "normal teardown did not issue exactly one master exit",
        ));
    }
    wait_for_not_connectable(SocketAddr::new(IpAddr::V4(address), local_port))?;
    let cancel_commands = runner
        .invocations()
        .iter()
        .filter(|invocation| {
            invocation
                .args
                .windows(2)
                .any(|args| args[0] == "-O" && args[1] == "cancel")
        })
        .count();
    if cancel_commands != 0 {
        return Err(io::Error::other(
            "normal teardown issued a per-mapping cancel command",
        ));
    }
    let audit_file = role_path("HERDR_OPENSSH_AUDIT")?;
    fs::write(
        audit_file,
        format!(
            "exit_commands={}\ncancel_commands={cancel_commands}\n",
            control.exit_command_count()
        ),
    )?;
    drop(worker);
    control.disarm();
    Ok(())
}

fn run_orphan_launcher_role() -> io::Result<()> {
    let control = ManagedControl::from_role_environment()?;
    control.start()?;
    let address = role_string("HERDR_OPENSSH_ADDRESS")?
        .parse::<Ipv4Addr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid role address"))?;
    let local_port = role_u16("HERDR_OPENSSH_LOCAL_PORT")?;
    let remote_port = role_u16("HERDR_OPENSSH_REMOTE_PORT")?;
    let worker = ControlWorker::start(
        control.authority(),
        Arc::new(ProcessCommandRunner::default()),
        PROCESS_TIMEOUT,
    );
    let specification = ForwardSpec {
        local_address: LoopbackAddress::Ipv4(address.octets()),
        local_port,
        remote_address: LoopbackAddress::Ipv4(address.octets()),
        remote_port,
    };
    let result = submit_and_receive(&worker, 1, ControlOperation::Forward(specification))?;
    if result.result != ControlResult::Succeeded {
        return Err(io::Error::other(
            "orphan role could not create its listener",
        ));
    }
    wait_for_connectable(SocketAddr::new(IpAddr::V4(address), local_port))?;
    let ready_file = role_path("HERDR_OPENSSH_READY")?;
    fs::write(
        ready_file,
        format!(
            "launcher_pid={}\nmaster_pid={}\nlistener={}\ncontrol_ready=1\n",
            std::process::id(),
            control.master_pid()?,
            local_port,
        ),
    )?;
    loop {
        std::thread::park_timeout(Duration::from_secs(1));
    }
}

fn wait_for_teardown_command(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + NORMAL_TEARDOWN_TIMEOUT;
    loop {
        match fs::read_to_string(path) {
            Ok(command) if command == "exit\n" => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid normal teardown command",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "normal teardown command timed out",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_reaped_child(
    child: &mut ReapedChild,
    timeout: Duration,
    label: &str,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            child.0.take();
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{label} timed out"),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn assert_normal_teardown_complete(
    control: &Path,
    listener: SocketAddr,
    master_pid: u32,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        let listener_gone =
            TcpStream::connect_timeout(&listener, Duration::from_millis(50)).is_err();
        if listener_gone && !control.exists() && !process_exists(master_pid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "normal teardown retained its listener, control socket, or master",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_file(path: &Path, child: &mut ReapedChild) -> io::Result<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if path.is_file() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "orphan launcher exited before readiness ({status})"
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "orphan launcher readiness timed out",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn parse_published_value(contents: &str, key: &str) -> io::Result<u64> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing readiness identity"))?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid readiness identity"))
}

fn parse_control_pid(output: &str) -> io::Result<u32> {
    let marker = "pid=";
    let start = output
        .find(marker)
        .map(|index| index + marker.len())
        .ok_or_else(|| io::Error::other("OpenSSH control check did not report master pid"))?;
    let digits = output[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits
        .parse::<u32>()
        .map_err(|_| io::Error::other("OpenSSH control check reported invalid master pid"))
}

fn process_exists(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn assert_process_gone(pid: u32) -> io::Result<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "expired OpenSSH master process still exists",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn role_path(name: &str) -> io::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing role path"))
}

fn role_string(name: &str) -> io::Result<String> {
    std::env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "missing role value"))
}

fn role_u16(name: &str) -> io::Result<u16> {
    role_string(name)?
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid role port"))
}

struct OpenSshHarness {
    root: PathBuf,
    ssh: PathBuf,
    sshd: Child,
    master: Option<Child>,
    target: String,
    config: PathBuf,
    control: PathBuf,
    identity: PathBuf,
    known_hosts: PathBuf,
    server_port: u16,
}

impl OpenSshHarness {
    fn start() -> io::Result<Self> {
        let root = create_private_temp_dir()?;
        let result = Self::start_in(root.clone());
        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result
    }

    fn start_in(root: PathBuf) -> io::Result<Self> {
        verify_private_directory(&root)?;
        let ssh = find_program("ssh", &[])?;
        let sshd = find_program("sshd", &[Path::new("/usr/sbin/sshd")])?;
        let ssh_keygen = find_program("ssh-keygen", &[])?;
        require_openssh_6_7_or_newer(&ssh)?;
        require_openssh_6_7_or_newer(&sshd)?;

        let host_key = root.join("host_ed25519");
        let identity = root.join("client_ed25519");
        generate_ed25519_key(&ssh_keygen, &host_key)?;
        generate_ed25519_key(&ssh_keygen, &identity)?;
        let authorized_keys = root.join("authorized_keys");
        fs::write(&authorized_keys, fs::read(root.join("client_ed25519.pub"))?)?;
        let known_hosts = root.join("known_hosts");
        let host_public = fs::read_to_string(root.join("host_ed25519.pub"))?;
        fs::write(&known_hosts, format!("herdr-openssh-harness {host_public}"))?;
        let config = root.join("empty_config");
        fs::write(&config, [])?;
        let control = root.join("control.sock");
        let server_port_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let server_port = server_port_reservation.local_addr()?.port();
        let username = current_username()?;
        let target = format!("{username}@herdr-openssh-harness");
        let sshd_config = root.join("sshd_config");
        fs::write(
            &sshd_config,
            format!(
                "Port {server_port}\n\
                 ListenAddress 127.0.0.1\n\
                 HostKey {}\n\
                 PidFile {}\n\
                 AuthorizedKeysFile {}\n\
                 AuthenticationMethods publickey\n\
                 PubkeyAuthentication yes\n\
                 PasswordAuthentication no\n\
                 KbdInteractiveAuthentication no\n\
                 ChallengeResponseAuthentication no\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 PermitRootLogin no\n\
                 PermitEmptyPasswords no\n\
                 AllowAgentForwarding no\n\
                 AllowTcpForwarding local\n\
                 GatewayPorts no\n\
                 X11Forwarding no\n\
                 PermitTunnel no\n\
                 PermitUserEnvironment no\n\
                 PermitTTY no\n\
                 UseDNS no\n\
                 LogLevel QUIET\n",
                host_key.display(),
                root.join("sshd.pid").display(),
                authorized_keys.display(),
            ),
        )?;
        let mut sshd_check = isolated_command(&sshd);
        sshd_check.arg("-t").arg("-f").arg(&sshd_config);
        run_checked(&mut sshd_check, PROCESS_TIMEOUT, "sshd configuration check")?;
        drop(server_port_reservation);
        let sshd_child = isolated_command(&sshd)
            .arg("-D")
            .arg("-e")
            .arg("-f")
            .arg(&sshd_config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| actionable("start unprivileged sshd", error))?;
        let mut harness = Self {
            root,
            ssh,
            sshd: sshd_child,
            master: None,
            target,
            config,
            control,
            identity,
            known_hosts,
            server_port,
        };
        harness.wait_for_sshd()?;
        harness.start_master(false)?;
        Ok(harness)
    }

    fn authority(&self) -> ControlAuthority {
        ControlAuthority::new(self.target.clone(), self.control.clone())
    }

    fn wait_for_sshd(&mut self) -> io::Result<()> {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.server_port);
        let deadline = Instant::now() + READINESS_TIMEOUT;
        loop {
            if let Some(status) = self.sshd.try_wait()? {
                return Err(io::Error::other(format!(
                    "unprivileged sshd exited before readiness ({status}); install/configure OpenSSH server for unprivileged tests"
                )));
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "unprivileged sshd did not become ready",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn start_master(&mut self, background: bool) -> io::Result<()> {
        let child = self
            .master_invocation(background)
            .spawn()
            .map_err(|error| actionable("start managed OpenSSH master", error))?;
        self.master = Some(child);
        let deadline = Instant::now() + READINESS_TIMEOUT;
        loop {
            if self.control_check()? {
                return Ok(());
            }
            if let Some(status) = self
                .master
                .as_mut()
                .and_then(|child| child.try_wait().ok())
                .flatten()
            {
                self.master = None;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "managed OpenSSH master exited before readiness ({status})"
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed OpenSSH control socket did not become ready",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn master_invocation(&self, background: bool) -> MasterInvocation {
        MasterInvocation::new(
            &self.ssh,
            &self.config,
            &self.control,
            &self.identity,
            &self.known_hosts,
            &self.target,
            self.server_port,
            background,
        )
    }

    fn control_check(&self) -> io::Result<bool> {
        let status = wait_bounded(
            &mut self.control_command("check"),
            PROCESS_TIMEOUT,
            "OpenSSH control check",
        )?;
        Ok(status.success())
    }

    fn master_pid(&self) -> io::Result<u32> {
        let mut command = self.control_command("check");
        command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let status = wait_for_child(&mut child, PROCESS_TIMEOUT, "OpenSSH control check")?;
        let mut output = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut output)?;
        }
        if !status.success() {
            return Err(io::Error::other("managed OpenSSH master is not running"));
        }
        let marker = "pid=";
        let start = output
            .find(marker)
            .map(|index| index + marker.len())
            .ok_or_else(|| io::Error::other("OpenSSH control check did not report master pid"))?;
        let digits = output[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        digits
            .parse::<u32>()
            .map_err(|_| io::Error::other("OpenSSH control check reported invalid master pid"))
    }

    fn kill_master(&mut self) -> io::Result<()> {
        let pid = self.master_pid()?;
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(mut master) = self.master.take() {
            let _ = master.wait();
        }
        let deadline = Instant::now() + READINESS_TIMEOUT;
        while self.control_check().unwrap_or(false) {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "killed OpenSSH master still answered control checks",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    fn control_command(&self, operation: &str) -> Command {
        let mut command = isolated_command(&self.ssh);
        command
            .arg("-F")
            .arg(&self.config)
            .arg("-S")
            .arg(&self.control)
            .arg("-O")
            .arg(operation)
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg(&self.target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    fn exit_master(&mut self) -> io::Result<()> {
        if self.master.is_none() && !self.control.exists() {
            return Ok(());
        }
        let status = wait_bounded(
            &mut self.control_command("exit"),
            PROCESS_TIMEOUT,
            "OpenSSH master exit",
        )?;
        if !status.success() {
            return Err(io::Error::other("OpenSSH master exit command failed"));
        }
        let deadline = Instant::now() + READINESS_TIMEOUT;
        if let Some(mut master) = self.master.take() {
            loop {
                if master.try_wait()?.is_some() {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = master.kill();
                    let _ = master.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "managed OpenSSH master did not exit",
                    ));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        while self.control.exists() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed OpenSSH control socket remained after exit",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }
}

impl Drop for OpenSshHarness {
    fn drop(&mut self) {
        if self.control.exists() {
            let _ = wait_bounded(
                &mut self.control_command("exit"),
                Duration::from_secs(2),
                "OpenSSH cleanup exit",
            );
        }
        if let Some(mut master) = self.master.take() {
            let _ = master.kill();
            let _ = master.wait();
        }
        let _ = self.sshd.kill();
        let _ = self.sshd.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct EchoServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl EchoServer {
    fn start(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let thread_accepted = accepted.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        thread_accepted.fetch_add(1, Ordering::AcqRel);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut bytes = [0_u8; 256];
                        if let Ok(count) = stream.read(&mut bytes) {
                            let _ = stream.write_all(&bytes[..count]);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            accepted,
            thread: Some(thread),
        })
    }

    fn accepted_connections(&self) -> u64 {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(50));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn expected_control_invocation(
    harness: &OpenSshHarness,
    operation: &str,
    specification: ForwardSpec,
) -> ControlInvocation {
    ControlInvocation {
        program: "ssh".to_string(),
        args: vec![
            "-F".to_string(),
            "/dev/null".to_string(),
            "-S".to_string(),
            harness.control.to_string_lossy().into_owned(),
            "-O".to_string(),
            operation.to_string(),
            "-L".to_string(),
            specification.ssh_value(),
            harness.target.clone(),
        ],
    }
}

fn assert_round_trip(address: SocketAddr, payload: &[u8]) {
    let mut stream = connect_bounded(address).expect("connect to forwarded listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set forwarded read timeout");
    stream.write_all(payload).expect("write forwarded payload");
    let mut received = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut received)
        .expect("read forwarded payload");
    assert_eq!(received, payload);
}

fn wait_for_connectable(address: SocketAddr) -> io::Result<()> {
    connect_bounded(address).map(drop)
}

fn connect_bounded(address: SocketAddr) -> io::Result<TcpStream> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(50)) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn assert_not_connectable(address: SocketAddr) {
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
        "unexpected listener on negative probe address"
    );
}

fn wait_for_not_connectable(address: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_err() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "listener remained after cancellation",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn reserve_port(address: IpAddr) -> io::Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(address, 0))?;
    listener.local_addr().map(|address| address.port())
}

fn reserve_dual_stack_port() -> io::Result<u16> {
    for _ in 0..64 {
        let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = ipv4.local_addr()?.port();
        match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
            Ok(ipv6) => {
                drop(ipv6);
                drop(ipv4);
                return Ok(port);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "could not reserve a dual-stack loopback port",
    ))
}

fn localhost_specs(local_port: u16, remote_port: u16) -> (ForwardSpec, ForwardSpec) {
    (
        ForwardSpec {
            local_address: LoopbackAddress::Ipv4(Ipv4Addr::LOCALHOST.octets()),
            local_port,
            remote_address: LoopbackAddress::Ipv4(Ipv4Addr::LOCALHOST.octets()),
            remote_port,
        },
        ForwardSpec {
            local_address: LoopbackAddress::Ipv6,
            local_port,
            remote_address: LoopbackAddress::Ipv6,
            remote_port,
        },
    )
}

#[cfg(target_os = "linux")]
fn representative_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(127, 42, 0, 9)
}

#[cfg(target_os = "macos")]
fn representative_ipv4() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

fn negative_ipv4(address: Ipv4Addr) -> Ipv4Addr {
    if address == Ipv4Addr::LOCALHOST {
        Ipv4Addr::new(127, 0, 0, 2)
    } else {
        Ipv4Addr::LOCALHOST
    }
}

fn create_private_temp_dir() -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    let base = std::env::temp_dir();
    #[cfg(target_os = "macos")]
    let base = PathBuf::from("/tmp");
    for _ in 0..64 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = base.join(format!(
            "herdr-openssh-{}-{sequence}-{nanos}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create unique private OpenSSH test directory",
    ))
}

fn verify_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OpenSSH test directory is not mode 0700",
        ));
    }
    Ok(())
}

fn find_program(name: &str, preferred: &[&Path]) -> io::Result<PathBuf> {
    for candidate in preferred {
        if candidate.is_file() {
            return Ok((*candidate).to_path_buf());
        }
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} not found; install OpenSSH client and server"),
        ));
    };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{name} not found; install OpenSSH client and server"),
    ))
}

fn require_openssh_6_7_or_newer(program: &Path) -> io::Result<()> {
    let mut command = isolated_command(program);
    command.arg("-V").stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let status = wait_for_child(&mut child, PROCESS_TIMEOUT, "OpenSSH version check")?;
    let mut version = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_string(&mut version)?;
    }
    if !status.success() || !openssh_version_at_least_6_7(&version) {
        return Err(io::Error::other(
            "OpenSSH 6.7 or newer is required for the listener harness",
        ));
    }
    Ok(())
}

fn openssh_version_at_least_6_7(version: &str) -> bool {
    let Some(version) = version.trim().strip_prefix("OpenSSH_") else {
        return false;
    };
    let numeric = version
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .next()
        .unwrap_or_default();
    let mut parts = numeric.split('.');
    let Some(major) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
        return false;
    };
    let Some(minor) = parts.next().and_then(|part| part.parse::<u32>().ok()) else {
        return false;
    };
    (major, minor) >= (6, 7)
}

fn generate_ed25519_key(keygen: &Path, path: &Path) -> io::Result<()> {
    let mut command = isolated_command(keygen);
    command
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-f")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_checked(
        &mut command,
        PROCESS_TIMEOUT,
        "temporary Ed25519 key generation",
    )
}

fn current_username() -> io::Result<String> {
    let uid = unsafe { libc::geteuid() };
    let mut password: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut password,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || password.pw_name.is_null() {
        return Err(io::Error::other(
            "could not resolve current account for unprivileged sshd",
        ));
    }
    let username = unsafe { CStr::from_ptr(password.pw_name) }
        .to_str()
        .map_err(|_| io::Error::other("current account name is not UTF-8"))?;
    Ok(username.to_string())
}

fn isolated_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env_remove("HOME")
        .env_remove("SSH_AUTH_SOCK");
    command
}

fn run_checked(command: &mut Command, timeout: Duration, label: &str) -> io::Result<()> {
    let status = wait_bounded(command, timeout, label)?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{label} failed ({status})")))
    }
}

fn wait_bounded(command: &mut Command, timeout: Duration, label: &str) -> io::Result<ExitStatus> {
    let mut child = command.spawn().map_err(|error| actionable(label, error))?;
    wait_for_child(&mut child, timeout, label)
}

fn wait_for_child(child: &mut Child, timeout: Duration, label: &str) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{label} timed out and was reaped"),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn actionable(label: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{label}: {error}; install/configure OpenSSH client and server"),
    )
}
