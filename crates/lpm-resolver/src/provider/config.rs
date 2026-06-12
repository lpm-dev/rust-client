use super::prelude::*;

impl LpmDependencyProvider {
    pub fn new(
        client: Arc<RegistryClient>,
        rt: Handle,
        root_deps: HashMap<String, String>,
    ) -> Self {
        LpmDependencyProvider {
            client,
            rt,
            cache: Arc::new(DashMap::new()),
            notify_map: Arc::new(DashMap::new()),
            // Default to Proxy; callers with a walker wire in the full
            // RouteTable via `with_route_table`. Empty npmrc → no Custom
            // routes, preserving fetch semantics for pre-npmrc callers.
            route_table: RouteTable::from_mode_only(RouteMode::Proxy),
            fetch_wait_timeout: Duration::ZERO,
            walker_done: Arc::new(AtomicBool::new(false)),
            metrics: StreamingBfsMetrics::new(),
            root_deps,
            split_packages: HashSet::new(),
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            platform_skipped: RefCell::new(0),
            policy: ResolverPolicy::default(),
            root_aliases: RefCell::new(HashMap::new()),
            range_cache: RefCell::new(HashMap::new()),
            include_optional_dependencies: true,
        }
    }

    /// Create a provider with multi-version splitting for specific packages.
    pub fn new_with_splits(
        client: Arc<RegistryClient>,
        rt: Handle,
        root_deps: HashMap<String, String>,
        splits: HashSet<String>,
    ) -> Self {
        LpmDependencyProvider {
            client,
            rt,
            cache: Arc::new(DashMap::new()),
            notify_map: Arc::new(DashMap::new()),
            // Default to Proxy; callers with a walker wire in the full
            // RouteTable via `with_route_table`. Empty npmrc → no Custom
            // routes, preserving fetch semantics for pre-npmrc callers.
            route_table: RouteTable::from_mode_only(RouteMode::Proxy),
            fetch_wait_timeout: Duration::ZERO,
            walker_done: Arc::new(AtomicBool::new(false)),
            metrics: StreamingBfsMetrics::new(),
            root_deps,
            split_packages: splits,
            overrides: OverrideSet::empty(),
            batch_disabled: RefCell::new(false),
            platform_skipped: RefCell::new(0),
            policy: ResolverPolicy::default(),
            root_aliases: RefCell::new(HashMap::new()),
            range_cache: RefCell::new(HashMap::new()),
            include_optional_dependencies: true,
        }
    }

    pub fn with_include_optional_dependencies(mut self, include: bool) -> Self {
        self.include_optional_dependencies = include;
        self
    }

    pub fn with_policy(mut self, policy: ResolverPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Attach an externally-owned shared cache + notify map (the one the
    /// BFS walker is populating concurrently). Also sets `fetch_wait_timeout`
    /// so `ensure_cached`'s wait-loop actually waits, and threads the
    /// [`WalkerDone`] flag so the wait-loop can short-circuit on a
    /// terminated walker without burning the timeout.
    #[allow(dead_code)] // wired by install.rs orchestration
    pub fn with_shared_cache(
        mut self,
        cache: SharedCache,
        notify_map: NotifyMap,
        walker_done: WalkerDone,
        fetch_wait_timeout: Duration,
    ) -> Self {
        self.cache = cache;
        self.notify_map = notify_map;
        self.walker_done = walker_done;
        self.fetch_wait_timeout = fetch_wait_timeout;
        self
    }

    /// Set the escape-hatch route mode. Applies to both the provider's
    /// miss-path fetches AND any walker attached via [`Self::with_shared_cache`].
    #[allow(dead_code)] // wired by install.rs orchestration
    pub fn with_route_mode(mut self, mode: RouteMode) -> Self {
        self.route_table = RouteTable::from_mode_only(mode);
        self
    }

    /// Supply the full `RouteTable` so `.npmrc`-declared custom registries
    /// reach the per-package fetch dispatcher.
    pub fn with_route_table(mut self, table: RouteTable) -> Self {
        self.route_table = table;
        self
    }

    /// Attach an externally-owned metrics object so the same counters
    /// accumulate across split-retry passes (each pass creates a new
    /// provider instance; the shared `Arc<AtomicU64>` inside
    /// `StreamingBfsMetrics` survives).
    pub fn with_streaming_metrics(mut self, metrics: StreamingBfsMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Install the fully-parsed override set. The set is owned by the
    /// provider for the duration of resolution; the resolver records every
    /// applied override into its internal hits buffer.
    ///
    /// **Important**: any package targeted by a path-selector override
    /// MUST also be in the `split_packages` set so PubGrub creates the
    /// per-parent identities the lookup expects. Callers can use
    /// [`OverrideSet::split_targets`] to seed the split set, then call
    /// `with_overrides` here. The two-step is intentional — keeping the
    /// split set passed at construction time preserves the existing
    /// API surface used by the split-retry resolver.
    pub fn with_overrides(mut self, overrides: OverrideSet) -> Self {
        self.overrides = overrides;
        self
    }
}
