//! Dashboard application state.

use crate::log_buffer::LogBuffer;

/// Status of a service in the dashboard.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
	Starting,
	WaitingForDep(String),
	Ready,
	Crashed(String),
	Stopped,
}

impl ServiceStatus {
	pub fn icon(&self) -> &str {
		match self {
			ServiceStatus::Starting => "○",
			ServiceStatus::WaitingForDep(_) => "⟳",
			ServiceStatus::Ready => "●",
			ServiceStatus::Crashed(_) => "✖",
			ServiceStatus::Stopped => "■",
		}
	}

	pub fn label(&self) -> String {
		match self {
			ServiceStatus::Starting => "starting".into(),
			ServiceStatus::WaitingForDep(dep) => format!("waiting for {dep}"),
			ServiceStatus::Ready => "ready".into(),
			ServiceStatus::Crashed(msg) => format!("crashed: {msg}"),
			ServiceStatus::Stopped => "stopped".into(),
		}
	}
}

/// State for a single service in the dashboard.
pub struct ServiceState {
	pub name: String,
	pub port: Option<u16>,
	pub status: ServiceStatus,
	pub logs: LogBuffer,
}

/// The main dashboard application state.
pub struct DashboardApp {
	pub services: Vec<ServiceState>,
	pub selected_service: usize,
	pub scroll_offset: usize,
	pub tunnel_url: Option<String>,
	pub network_ip: Option<String>,
	pub https: bool,
}

impl DashboardApp {
	pub fn new(services: Vec<ServiceState>) -> Self {
		Self {
			services,
			selected_service: 0,
			scroll_offset: 0,
			tunnel_url: None,
			network_ip: None,
			https: false,
		}
	}

	pub fn select_next(&mut self) {
		if !self.services.is_empty() {
			self.selected_service = (self.selected_service + 1) % self.services.len();
			self.scroll_offset = 0;
		}
	}

	pub fn select_prev(&mut self) {
		if !self.services.is_empty() {
			self.selected_service = if self.selected_service == 0 {
				self.services.len() - 1
			} else {
				self.selected_service - 1
			};
			self.scroll_offset = 0;
		}
	}

	pub fn scroll_up(&mut self) {
		if self.scroll_offset > 0 {
			self.scroll_offset -= 1;
		}
	}

	pub fn scroll_down(&mut self) {
		if let Some(svc) = self.services.get(self.selected_service) {
			if self.scroll_offset < svc.logs.len().saturating_sub(1) {
				self.scroll_offset += 1;
			}
		}
	}

	pub fn push_log(&mut self, service_index: usize, line: &str) {
		if let Some(svc) = self.services.get_mut(service_index) {
			svc.logs.push(line.to_string());
		}
	}
}
