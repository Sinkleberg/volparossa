//! Deterministic selector delivery after real nested handshakes; no historical-cause claim.

use super::*;
use crate::content::{ContentRuntime, fixture_correlation};
use volparossa_content::{
    private_storage::protocol::StorageChallenge,
    provider::{ProviderError, activity::Observer as _, serve_publication_with_activity},
};
use volparossa_local_control::{
    StorageFixtureCorrelationAction as Action, StorageFixtureCorrelationPhase as Phase,
    StorageFixtureCorrelationRequest as Query, StorageFixtureCorrelationState as State,
    StorageFixtureCorrelationTerminal as Terminal,
};
use wire::begin_observation::{Observer, ReadFailure, ReadStep};

#[path = "selector_gate.rs"]
mod selector_gate;
use selector_gate::Gate;

const UID: u32 = 1000;
const CLIENT_OPERATION: Duration = Duration::from_secs(120);
const CLOSE_CEILING: Duration = Duration::from_secs(25);
// Setup/cleanup ceiling is separate from the 25s assertion at the held read.
const WHOLE_CASE: Duration = Duration::from_secs(60);

struct Trace {
    phase: Mutex<Option<wire::begin_observation::Phase>>,
    step: Mutex<Option<ReadStep>>,
    failure: Mutex<Option<ReadFailure>>,
    length: Mutex<Option<oneshot::Sender<()>>>,
}

impl Trace {
    fn new() -> (Self, oneshot::Receiver<()>) {
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                phase: Mutex::new(None),
                step: Mutex::new(None),
                failure: Mutex::new(None),
                length: Mutex::new(Some(sender)),
            },
            receiver,
        )
    }
}

impl Observer for Trace {
    fn phase(&self, phase: wire::begin_observation::Phase) {
        *self.phase.lock().unwrap() = Some(phase);
    }
    fn read_step(&self, step: ReadStep) {
        *self.step.lock().unwrap() = Some(step);
        if step == ReadStep::LengthRead {
            if let Some(sender) = self.length.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
    }
    fn read_failure(&self, failure: ReadFailure) {
        *self.failure.lock().unwrap() = Some(failure);
    }
}

fn query(action: Action) -> Query {
    Query {
        version: 1,
        action: action as i32,
        epoch: vec![9; 16],
        fingerprints: Vec::new(),
        target: None,
    }
}

async fn correlated(runtime: &ContentRuntime, released: bool) -> bool {
    let valid = async {
        let clients = runtime
            .fixture_correlation(UID, &query(Action::Clients))
            .await
            .ok()?;
        if clients.incomplete || clients.records.len() != 1 {
            return None;
        }
        let fingerprint = clients.records[0].fingerprint.clone()?;
        let mut request = query(Action::Providers);
        request.fingerprints.push(fingerprint.clone());
        let providers = runtime.fixture_correlation(UID, &request).await.ok()?;
        Some(
            !providers.incomplete
                && providers.records.len() == 1
                && providers.records[0].fingerprint.as_ref() == Some(&fingerprint)
                && (released
                    || (providers.records[0].phase == Phase::SelectorRead as i32
                        && providers.records[0].terminal == Terminal::OperationError as i32)),
        )
    }
    .await
    .unwrap_or(false);
    // Disarm joins the collector's existing cleanup task before any assertion,
    // including when an I/O assertion already failed inside a joined child task.
    let disarmed = runtime.fixture_correlation(UID, &query(Action::Disarm)).await;
    valid && matches!(disarmed, Ok(response) if response.state == State::Disarmed as i32)
}

async fn provider(
    listener: TcpListener,
    fixture: Arc<Fixture>,
    runtime: Arc<ContentRuntime>,
    evidence: Arc<Evidence>,
    ready: oneshot::Sender<Instant>,
    expired: oneshot::Sender<Instant>,
    released: bool,
) {
    let guard = runtime.fixture_correlation.provider();
    let activity = runtime.provider_activity.begin();
    let observer = fixture_correlation::ProviderObserver {
        activity: &activity,
        fixture: &guard,
    };
    let (socket, _) = listener.accept().await.unwrap();
    let socket = fixture_correlation::Observed::provider(socket, &guard);
    let mut stream = fixture
        .provider_tls
        .accept_observed(socket, &guard)
        .await
        .unwrap();
    observer.enter(volparossa_content::provider::activity::Stage::RegistrySnapshot);
    let started = Instant::now();
    ready.send(started).unwrap();
    let mut failure = None;
    let limits = TransferLimits::default();
    assert_eq!(limits.exchange_timeout, Duration::from_secs(15));
    let result = serve_publication_with_activity(
        &mut stream,
        &fixture.registry,
        limits,
        &mut failure,
        &observer,
    )
    .await;
    if released {
        result.unwrap();
        observer.enter(volparossa_content::provider::activity::Stage::Closing);
        finish(&mut stream).await.unwrap();
        guard.finish(Terminal::Complete);
    } else {
        assert!(matches!(result, Err(ProviderError::Timeout)));
        assert!(
            failure.is_none(),
            "storage service must not have received a selector"
        );
        assert!(started.elapsed() >= limits.exchange_timeout);
        guard.finish(Terminal::OperationError);
        // Independent provider event, before the original error path drops TLS/TCP.
        // No test teardown, forced abort or gate release precedes this event.
        expired.send(Instant::now()).unwrap();
    }
    drop(stream);
    evidence.providers.fetch_add(1, SeqCst);
}

async fn exit(
    listener: volparossa_mptcp::MptcpListener,
    service: ExitService,
    outer: Arc<Outer>,
    evidence: Arc<Evidence>,
    gate: Arc<Gate>,
    released: bool,
) {
    let (socket, _) = listener.accept().await.unwrap();
    socket.require_negotiated().unwrap();
    let stream = outer.server.accept(socket, SCENARIO_LIMIT).await.unwrap();
    let mut stream = crate::mptcp_flow_runtime::tls_for_test(stream).unwrap();
    let mut replay = ReplayCache::new(16).unwrap();
    let authorized = read_authorized_open_tcp(
        &mut stream,
        &TcpAuthorizationScope::new(&outer.route, &outer.policy),
        crate::unix_millis(),
        TimePolicy::default(),
        &mut replay,
        SCENARIO_LIMIT,
    )
    .await
    .unwrap();
    assert_eq!(authorized.hostname(), Some(HOSTNAME));
    assert_eq!(authorized.port(), PROVIDER_PORT);
    let limits = TcpEgressLimits::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
        StreamTransferLimits::new(128, 1024 * 1024, 1024 * 1024, Duration::from_secs(60)).unwrap(),
    )
    .unwrap();
    let result = service
        .run_tcp_egress(
            &authorized,
            Fragmented {
                inner: gate.wrap(stream),
                evidence: Arc::clone(&evidence),
            },
            crate::unix_millis(),
            limits,
        )
        .await;
    if released {
        let statistics = result.unwrap();
        assert!(statistics.client_to_exit_bytes > 0 && statistics.exit_to_client_bytes > 0);
    }
    let counts = service.dns_resolver().counts();
    assert_eq!(counts.trusted_fallback, 1);
    assert_eq!(
        counts.local_validated + counts.peer_validated + counts.upstream_validated,
        0
    );
    evidence.exits.fetch_add(1, SeqCst);
}

struct ClientControl {
    ready: oneshot::Receiver<Instant>,
    expired: oneshot::Receiver<Instant>,
    blocked: oneshot::Receiver<()>,
    gate: Arc<Gate>,
    released: bool,
}

async fn transport(
    endpoint: std::net::SocketAddr,
    outer: &Outer,
) -> impl AsyncRead + AsyncWrite + Unpin {
    let socket = volparossa_mptcp::connect(endpoint, None, Duration::from_secs(2))
        .await
        .unwrap();
    socket.require_negotiated().unwrap();
    let stream = outer
        .client
        .connect_preconnected(
            &outer.route,
            socket,
            ServerName::try_from(EXIT_NAME).unwrap(),
            crate::unix_millis(),
            SCENARIO_LIMIT,
        )
        .await
        .unwrap();
    let mut transport = crate::mptcp_flow_runtime::tls_for_test(stream).unwrap();
    let opening = outer
        .signed
        .sign_open_tcp(
            outer.policy.policy_hash(),
            HOSTNAME,
            PROVIDER_PORT,
            crate::unix_millis(),
        )
        .unwrap();
    write_open_tcp(&mut transport, &opening, SCENARIO_LIMIT)
        .await
        .unwrap();
    transport
}

type BeginResult = Result<Result<StorageChallenge, wire::WireError>, tokio::time::error::Elapsed>;

async fn closed_before_ceiling<F>(
    begin: F,
    expired: oneshot::Receiver<Instant>,
    deadline: Instant,
    trace: &Trace,
    gate: &Gate,
) where
    F: Future<Output = BeginResult>,
{
    let (provider_expired, returned) = tokio::join!(
        timeout_at(deadline, expired),
        timeout_at(deadline, async {
            let result = begin.await;
            (Instant::now(), result)
        }),
    );
    let provider_expired = provider_expired
        .expect("provider selector did not expire")
        .unwrap();
    let (returned_at, result) =
        returned.expect("provider close did not reach held LengthRead within 25s");
    assert!(returned_at >= provider_expired);
    assert!(
        gate.is_held(),
        "test released the forward gate before close propagation"
    );
    assert!(matches!(result.unwrap(), Err(wire::WireError::Io(_))));
    assert_eq!(
        *trace.phase.lock().unwrap(),
        Some(wire::begin_observation::Phase::ChallengeReadVerify)
    );
    assert_eq!(*trace.step.lock().unwrap(), Some(ReadStep::LengthRead));
    assert!(matches!(
        *trace.failure.lock().unwrap(),
        Some(ReadFailure::IoEof | ReadFailure::IoOther)
    ));
}

async fn begin<S: AsyncRead + AsyncWrite + Unpin>(
    inner: &mut S,
    fixture: &Fixture,
    operation_deadline: Instant,
    control: ClientControl,
) -> Option<StorageChallenge> {
    let provider_started = control.ready.await.unwrap();
    // Both authenticated handshakes returned. Pause only forwarding to the provider;
    // all original client writes/flushes and reverse close propagation remain real.
    control.gate.hold();
    let (trace, length) = Trace::new();
    let deadline = Instant::now() + CLOSE_CEILING;
    assert!(deadline < operation_deadline);
    let mut begin = Box::pin(timeout_at(
        operation_deadline,
        wire::begin_observed(inner, &fixture.grant, &trace),
    ));
    timeout_at(deadline, async {
        tokio::select! {
            () = async { length.await.unwrap(); control.blocked.await.unwrap(); } => {},
            _ = &mut begin => panic!("wire begin returned before the held LengthRead seam"),
        }
    })
    .await
    .expect("held LengthRead seam did not become observable");
    assert_eq!(*trace.step.lock().unwrap(), Some(ReadStep::LengthRead));
    if control.released {
        assert!(provider_started.elapsed() < TransferLimits::default().exchange_timeout);
        control.gate.release();
        let challenge = timeout_at(deadline, &mut begin)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(*trace.step.lock().unwrap(), Some(ReadStep::Verification));
        assert!(trace.failure.lock().unwrap().is_none());
        Some(challenge)
    } else {
        closed_before_ceiling(begin, control.expired, deadline, &trace, &control.gate).await;
        control.gate.release();
        None
    }
}

async fn client(
    endpoint: std::net::SocketAddr,
    fixture: Arc<Fixture>,
    outer: Arc<Outer>,
    runtime: Arc<ContentRuntime>,
    evidence: Arc<Evidence>,
    control: ClientControl,
) {
    let operation_started = Instant::now();
    let operation_deadline = operation_started + CLIENT_OPERATION;
    let mut transport = transport(endpoint, &outer).await;
    let guard = runtime.fixture_correlation.client(UID);
    guard.start_operation(Some(operation_started), CLIENT_OPERATION);
    guard.enter(Phase::TlsHandshake);
    let mut inner = connect(
        fixture_correlation::Observed::client(&mut transport, &guard),
        fixture.provider_peer,
        &fixture.provider_offer,
    )
    .await
    .unwrap();
    guard.enter(Phase::ClientChallenge);
    let released = control.released;
    if let Some(challenge) = begin(&mut inner, &fixture, operation_deadline, control).await {
        let lease = reserve_challenged(&fixture, &mut inner, 0, &challenge).await;
        assert!(evidence.leases.lock().unwrap().insert(lease));
        finish(&mut inner).await.unwrap();
        guard.finish(Terminal::Complete);
    } else {
        guard.finish(Terminal::OperationError);
    }
    drop(inner);
    if released {
        finish(&mut transport).await.unwrap();
    }
    drop(transport);
    evidence.clients.fetch_add(1, SeqCst);
}

struct Endpoints {
    client: std::net::SocketAddr,
    exit: volparossa_mptcp::MptcpListener,
    provider: TcpListener,
    dns: TcpListener,
}

struct Actors {
    fixture: Arc<Fixture>,
    outer: Arc<Outer>,
    runtime: Arc<ContentRuntime>,
    evidence: Arc<Evidence>,
    gate: Arc<Gate>,
    released: bool,
}

fn service(outer: &Outer, dns: std::net::SocketAddr) -> ExitService {
    let resolver = ExitResolver::default()
        .with_cache_enabled(false)
        .with_unbound_fallback(dns)
        .unwrap();
    let mut service = ExitService::new(
        ExitServiceConfig::enabled(
            outer.signed.exit_node_id(),
            Bandwidth::new(100, 100).unwrap(),
            4,
            300,
            30,
            128,
        ),
        outer.policy.clone(),
        None,
    )
    .unwrap();
    service.set_dns_resolver(Arc::new(resolver));
    service
}

fn start(
    tasks: &mut JoinSet<()>,
    endpoints: Endpoints,
    actors: Actors,
    blocked: oneshot::Receiver<()>,
) {
    let service = service(&actors.outer, endpoints.dns.local_addr().unwrap());
    let (ready, ready_received) = oneshot::channel();
    let (expired, expired_received) = oneshot::channel();
    tasks.spawn(Box::pin(dns_queries(
        endpoints.dns,
        Arc::clone(&actors.evidence),
        1,
    )));
    tasks.spawn(Box::pin(provider(
        endpoints.provider,
        Arc::clone(&actors.fixture),
        Arc::clone(&actors.runtime),
        Arc::clone(&actors.evidence),
        ready,
        expired,
        actors.released,
    )));
    tasks.spawn(Box::pin(exit(
        endpoints.exit,
        service,
        Arc::clone(&actors.outer),
        Arc::clone(&actors.evidence),
        Arc::clone(&actors.gate),
        actors.released,
    )));
    tasks.spawn(Box::pin(client(
        endpoints.client,
        actors.fixture,
        actors.outer,
        actors.runtime,
        actors.evidence,
        ClientControl {
            ready: ready_received,
            expired: expired_received,
            blocked,
            gate: actors.gate,
            released: actors.released,
        },
    )));
}

async fn scenario(released: bool) {
    require_isolation();
    let before = socket_identities();
    let fixture = Arc::new(Fixture::new());
    let outer = Arc::new(Outer::new());
    let evidence = Arc::new(Evidence::default());
    let runtime =
        Arc::new(ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap());
    runtime
        .fixture_correlation(UID, &query(Action::Arm))
        .await
        .unwrap();
    let listener = volparossa_mptcp::listen("127.0.0.1:0".parse().unwrap(), 4).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let provider_listener = TcpListener::bind((PROVIDER_ADDRESS, PROVIDER_PORT))
        .await
        .unwrap();
    let dns = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoints = Endpoints {
        client: endpoint,
        exit: listener,
        provider: provider_listener,
        dns,
    };
    let (gate, blocked) = Gate::new();
    let actors = Actors {
        fixture,
        outer,
        runtime: Arc::clone(&runtime),
        evidence: Arc::clone(&evidence),
        gate: Arc::clone(&gate),
        released,
    };
    let mut tasks = JoinSet::new();
    start(&mut tasks, endpoints, actors, blocked);
    let result = timeout(WHOLE_CASE, async {
        while let Some(completed) = tasks.join_next().await {
            completed?;
        }
        Ok::<_, tokio::task::JoinError>(())
    })
    .await;
    // Every outcome releases the gate, aborts and joins all tasks, including DNS.
    gate.release();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let correlation_complete = correlated(&runtime, released).await;
    assert!(tasks.is_empty());
    assert_eq!(
        socket_identities(),
        before,
        "owned socket survived selector test cleanup"
    );
    assert!(
        matches!(result, Ok(Ok(()))),
        "selector close scenario failed: {result:?}"
    );
    assert!(
        correlation_complete,
        "controlled TLS prefix correlation was incomplete"
    );
    for count in [
        &evidence.clients,
        &evidence.providers,
        &evidence.exits,
        &evidence.dns_a,
        &evidence.dns_aaaa,
    ] {
        assert_eq!(count.load(SeqCst), 1);
    }
    assert_eq!(evidence.leases.lock().unwrap().len(), usize::from(released));
    assert!(evidence.partial_reads.load(SeqCst) > 2);
    assert_eq!(Arc::strong_count(&evidence), 1);
}

#[tokio::test]
#[ignore = "requires exact hosted disposable content-egress namespace and genuine Linux MPTCP"]
async fn released_selector_reaches_verified_challenge_and_signed_reserve() {
    scenario(true).await;
}

#[tokio::test]
#[ignore = "requires exact hosted disposable content-egress namespace and genuine Linux MPTCP"]
async fn held_selector_default_provider_deadline_propagates_io_before_operation_deadline() {
    scenario(false).await;
}
