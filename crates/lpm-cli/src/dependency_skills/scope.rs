//! Whose dependency skills a command works on: a project's, under its
//! `package.json`, or the user's global packages', under the global
//! policy. Each scope reads, edits, previews and reconciles its own policy.

use super::edit::PolicyEdit;
use super::global::GlobalSkills;
use super::inspect::{Inspector, Subject};
use super::state::{Site, StoredState};
use super::{ReconcileReport, Settings};
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

pub(crate) enum Scope {
    /// The project whose policy applies: the workspace root in a workspace.
    Project(PathBuf),
    Global(Box<GlobalSkills>),
}

impl Scope {
    /// The scope of `project_dir`, or the global packages' when `global`.
    pub(crate) fn resolve(project_dir: &Path, global: bool) -> Result<Self, LpmError> {
        Ok(if global {
            Self::Global(Box::new(GlobalSkills::locate()?))
        } else {
            Self::Project(super::skills_root(project_dir))
        })
    }

    #[inline]
    pub(crate) fn is_global(&self) -> bool {
        matches!(self, Self::Global(_))
    }

    /// How messages name the file the policy lives in.
    pub(crate) fn policy_file(&self) -> &'static str {
        match self {
            Self::Project(_) => "package.json",
            Self::Global(_) => "the global skills policy",
        }
    }

    /// The command that names this scope, for hints.
    pub(crate) fn flag(&self) -> &'static str {
        match self {
            Self::Project(_) => "",
            Self::Global(_) => " --global",
        }
    }

    fn site(&self) -> Site {
        match self {
            Self::Project(root) => Site::project(root),
            Self::Global(global) => global.site().clone(),
        }
    }

    /// The policy document as it stands: the project's manifest, or the
    /// global policy object.
    pub(crate) fn document(&self) -> Result<serde_json::Value, LpmError> {
        match self {
            Self::Project(root) => super::plan::read_manifest(root),
            Self::Global(global) => global.policy_document(),
        }
    }

    /// The policy, read for an edit.
    pub(crate) fn edit(&self) -> Result<PolicyEdit, LpmError> {
        match self {
            Self::Project(root) => PolicyEdit::project(root),
            Self::Global(global) => PolicyEdit::global(
                global.lpm_root().clone(),
                global.policy_path().to_path_buf(),
            ),
        }
    }

    /// The LPM.dev global packages, by name and version, whose reviewed
    /// skills applying `document`, an edited policy, fetches first because
    /// their folders lack them; none for a project, whose installs fetch
    /// them.
    pub(crate) fn lpm_dev_sets_to_fetch(
        &self,
        document: &serde_json::Value,
        settings: Settings,
    ) -> Vec<(String, String)> {
        let Self::Global(global) = self else {
            return Vec::new();
        };
        let policy = super::policy::read_global_policy(document).policy;
        global
            .lpm_dev_sets_to_fetch(policy.as_ref(), settings)
            .into_iter()
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect()
    }

    /// The LPM.dev global packages, by name and version, whose reviewed
    /// skills haven't been fetched, for the picker to offer whole; none for
    /// a project, whose installs fetch them.
    pub(crate) fn lpm_dev_packages_without_sets(
        &self,
        settings: Settings,
    ) -> Vec<(String, String)> {
        let Self::Global(global) = self else {
            return Vec::new();
        };
        global
            .lpm_dev_packages_without_sets(settings)
            .into_iter()
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect()
    }

    pub(crate) fn inspector(&self, settings: Settings) -> Inspector<'_> {
        let subject = match self {
            Self::Project(root) => Subject::Project(root),
            Self::Global(global) => Subject::Global(global),
        };
        Inspector::new(subject, settings)
    }

    /// Refuses a change to the policy while a newer LPM's record of the
    /// links is in place: this LPM couldn't apply the change.
    pub(crate) fn ensure_links_are_ours(&self) -> Result<(), LpmError> {
        match super::state::read_state(&self.site()) {
            StoredState::Newer(reason) => Err(LpmError::Script(format!(
                "{reason}; update LPM before changing which dependency skills it links"
            ))),
            _ => Ok(()),
        }
    }

    /// Writes `edit` when `changed`, and reconciles the links. A project's
    /// policy is written and reconciled inside its install transaction. For
    /// the global packages, `client` first fetches the LPM.dev skills the
    /// policy may link that their folders lack; then, under the global
    /// transaction lock global installs take, a policy file that changed
    /// since the edit read it refuses the whole change before anything is
    /// written, and otherwise the sets and the policy are written. The links
    /// are reconciled under their own lock afterwards, from the global
    /// manifest as it stands then.
    pub(crate) async fn write_and_reconcile(
        &self,
        edit: &PolicyEdit,
        changed: bool,
        settings: Settings,
        client: Option<&lpm_registry::RegistryClient>,
    ) -> Result<ReconcileReport, LpmError> {
        match self {
            Self::Project(root) => {
                let apply = || -> Result<ReconcileReport, LpmError> {
                    self.ensure_links_are_ours()?;
                    if changed {
                        edit.write()?;
                    }
                    self.reconcile_now(settings)
                };
                crate::commands::trust::scope_project_policy_mutation(root, async { apply() }).await
            }
            Self::Global(global) => {
                let policy = super::policy::read_global_policy(&edit.value).policy;
                let fetched = match client {
                    Some(client) => {
                        super::fetch_global_lpm_dev_skills(
                            global,
                            policy.as_ref(),
                            settings,
                            client,
                        )
                        .await
                    }
                    None => Vec::new(),
                };
                let written = if changed || !fetched.is_empty() {
                    global.with_tx_lock(|| {
                        self.ensure_links_are_ours()?;
                        if changed {
                            edit.ensure_current()?;
                        }
                        let warnings = global.write_fetched_sets_locked(fetched)?;
                        if changed {
                            edit.write()?;
                        }
                        Ok(warnings)
                    })?
                } else {
                    self.ensure_links_are_ours()?;
                    Vec::new()
                };
                let mut report = self.reconcile_now(settings)?;
                report.warnings.splice(0..0, written);
                Ok(report)
            }
        }
    }

    /// Brings the links in line with the policy as it stands: for the
    /// global packages, after fetching the LPM.dev skills it may link that
    /// their folders lack, as [`Self::write_and_reconcile`] does.
    pub(crate) async fn sync(
        &self,
        settings: Settings,
        client: &lpm_registry::RegistryClient,
    ) -> Result<ReconcileReport, LpmError> {
        let Self::Global(global) = self else {
            return self.reconcile_now(settings);
        };
        let policy = global.read_policy().policy;
        let fetched =
            super::fetch_global_lpm_dev_skills(global, policy.as_ref(), settings, client).await;
        let written = global.write_fetched_sets(fetched)?;
        let mut report = self.reconcile_now(settings)?;
        report.warnings.splice(0..0, written);
        Ok(report)
    }

    /// Reconciles the links now, planning even when they look current.
    pub(crate) fn reconcile_now(&self, settings: Settings) -> Result<ReconcileReport, LpmError> {
        match self {
            Self::Project(root) => super::reconcile_now(root, settings),
            Self::Global(global) => super::reconcile_global_now(global, settings),
        }
    }

    /// What differs between the links and what the policy links now.
    pub(crate) fn drift(&self, settings: Settings) -> Result<Vec<String>, LpmError> {
        match self {
            Self::Project(root) => super::inspect::drift(root, settings),
            Self::Global(global) => super::inspect::drift_global(global, settings),
        }
    }
}
