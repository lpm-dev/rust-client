use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseInfo {
    owner_pid: u32,
}

#[derive(Debug, Default)]
pub struct RouteRegistry {
    next_lease_id: u64,
    routes: HashMap<String, RegisteredRoute>,
    leases: HashMap<RouteLeaseId, LeaseInfo>,
}

impl RouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_routes(
        &mut self,
        owner_pid: u32,
        routes: Vec<Route>,
    ) -> Result<RouteLeaseId, ProxyError> {
        if routes.is_empty() {
            return Err(ProxyError::EmptyRouteSet);
        }

        let lease_id = self.allocate_lease_id();
        let prepared = self.prepare_routes(lease_id, owner_pid, routes)?;
        self.leases.insert(lease_id, LeaseInfo { owner_pid });
        for route in prepared {
            self.routes.insert(route.host.clone(), route);
        }
        Ok(lease_id)
    }

    pub fn replace_routes(
        &mut self,
        lease_id: RouteLeaseId,
        routes: Vec<Route>,
    ) -> Result<(), ProxyError> {
        if routes.is_empty() {
            return Err(ProxyError::EmptyRouteSet);
        }

        let owner_pid = self
            .leases
            .get(&lease_id)
            .ok_or(ProxyError::UnknownLease(lease_id))?
            .owner_pid;
        let prepared = self.prepare_routes(lease_id, owner_pid, routes)?;
        self.release_routes_for_lease(lease_id);
        for route in prepared {
            self.routes.insert(route.host.clone(), route);
        }
        Ok(())
    }

    pub fn release(&mut self, lease_id: RouteLeaseId) -> usize {
        let removed = self.release_routes_for_lease(lease_id);
        self.leases.remove(&lease_id);
        removed
    }

    pub fn lookup_host(&self, host: &str) -> Option<&RegisteredRoute> {
        let host = canonical_host(host).ok()?;
        self.routes.get(&host)
    }

    pub fn lookup_host_header(&self, host_header: &str) -> Option<&RegisteredRoute> {
        let host = canonical_host_from_header(host_header).ok()?;
        self.routes.get(&host)
    }

    pub fn statuses(&self) -> Vec<RouteStatus> {
        let mut statuses: Vec<RouteStatus> = self
            .routes
            .values()
            .map(|route| RouteStatus {
                host: route.host.clone(),
                upstream_port: route.upstream_port,
                project_dir: route.project_dir.clone(),
                service: route.service.clone(),
                lease_id: route.lease_id,
                owner_pid: route.owner_pid,
            })
            .collect();
        statuses.sort_by(|a, b| a.host.cmp(&b.host));
        statuses
    }

    pub fn prune_dead_leases(&mut self) -> usize {
        self.prune_leases_with(process_is_running)
    }

    fn allocate_lease_id(&mut self) -> RouteLeaseId {
        self.next_lease_id += 1;
        RouteLeaseId(self.next_lease_id)
    }

    fn prepare_routes(
        &self,
        lease_id: RouteLeaseId,
        owner_pid: u32,
        routes: Vec<Route>,
    ) -> Result<Vec<RegisteredRoute>, ProxyError> {
        let mut seen = HashSet::with_capacity(routes.len());
        let mut prepared = Vec::with_capacity(routes.len());

        for route in routes {
            let host = canonical_host(&route.host)?;
            if !seen.insert(host.clone()) {
                return Err(ProxyError::DuplicateHostInRouteSet { host });
            }
            if let Some(existing) = self.routes.get(&host)
                && existing.lease_id != lease_id
            {
                return Err(ProxyError::HostAlreadyRegistered {
                    host,
                    lease_id: existing.lease_id,
                    owner_pid: existing.owner_pid,
                });
            }
            prepared.push(RegisteredRoute {
                host,
                upstream_port: route.upstream_port,
                project_dir: route.project_dir,
                service: route.service,
                lease_id,
                owner_pid,
            });
        }

        Ok(prepared)
    }

    fn release_routes_for_lease(&mut self, lease_id: RouteLeaseId) -> usize {
        let before = self.routes.len();
        self.routes.retain(|_, route| route.lease_id != lease_id);
        before - self.routes.len()
    }

    pub(crate) fn prune_leases_with(
        &mut self,
        mut owner_is_alive: impl FnMut(u32) -> bool,
    ) -> usize {
        let dead_leases: Vec<RouteLeaseId> = self
            .leases
            .iter()
            .filter_map(|(lease_id, info)| (!owner_is_alive(info.owner_pid)).then_some(*lease_id))
            .collect();
        let mut removed = 0;
        for lease_id in dead_leases {
            removed += self.release_routes_for_lease(lease_id);
            self.leases.remove(&lease_id);
        }
        removed
    }
}
