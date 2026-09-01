use super::prelude::*;
use console::{Key, Term};
use std::io;

pub(in crate::commands::config) const RELEASE_AGE_KEY: &str = "minimum-release-age-secs";
pub(in crate::commands::config) const RELEASE_AGE_POLICY_KEY: &str =
    crate::release_age_config::GLOBAL_POLICY_KEY;
pub(in crate::commands::config) const RELEASE_AGE_GUIDED_MENU_LABEL: &str =
    "Release age configuration";
pub(in crate::commands::config) const DEFAULT_RELEASE_AGE_SECS: u64 =
    crate::release_age_config::DEFAULT_MIN_RELEASE_AGE_SECS;
pub(in crate::commands::config) const CAUTIOUS_RELEASE_AGE_SECS: u64 = 3 * DEFAULT_RELEASE_AGE_SECS;
const RELEASE_AGE_EDITOR_HELP: &str =
    "Use ↑/↓ to move, ←/→ to change, Enter to save, Esc to cancel.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::commands::config) enum ReleaseAgeSelection {
    Default,
    Seconds(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseAgeChoice {
    Default,
    Cautious,
    Off,
    Custom,
}

impl ReleaseAgeChoice {
    const fn from_override(current: Option<u64>) -> Self {
        match current {
            None => Self::Default,
            Some(0) => Self::Off,
            Some(CAUTIOUS_RELEASE_AGE_SECS) => Self::Cautious,
            Some(_) => Self::Custom,
        }
    }

    const fn step(self, step: SelectionStep) -> Self {
        match (self, step) {
            (Self::Default, SelectionStep::Previous) => Self::Custom,
            (Self::Default, SelectionStep::Next) => Self::Cautious,
            (Self::Cautious, SelectionStep::Previous) => Self::Default,
            (Self::Cautious, SelectionStep::Next) => Self::Off,
            (Self::Off, SelectionStep::Previous) => Self::Cautious,
            (Self::Off, SelectionStep::Next) => Self::Custom,
            (Self::Custom, SelectionStep::Previous) => Self::Off,
            (Self::Custom, SelectionStep::Next) => Self::Default,
        }
    }

    const fn selection(self, custom_secs: u64) -> ReleaseAgeSelection {
        match self {
            Self::Default => ReleaseAgeSelection::Default,
            Self::Cautious => ReleaseAgeSelection::Seconds(CAUTIOUS_RELEASE_AGE_SECS),
            Self::Off => ReleaseAgeSelection::Seconds(0),
            Self::Custom => ReleaseAgeSelection::Seconds(custom_secs),
        }
    }

    const fn initial_value(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Cautious => "cautious",
            Self::Off => "off",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionStep {
    Previous,
    Next,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseAgeEditorSettings {
    policy: crate::release_age_config::ReleaseAgePolicy,
    age_choice: ReleaseAgeChoice,
    custom_secs: u64,
}

impl ReleaseAgeEditorSettings {
    fn from_overrides(
        age: Option<u64>,
        policy: Option<crate::release_age_config::ReleaseAgePolicy>,
    ) -> Self {
        let age_choice = ReleaseAgeChoice::from_override(age);
        let custom_secs = if age_choice == ReleaseAgeChoice::Custom {
            age.unwrap_or(DEFAULT_RELEASE_AGE_SECS)
        } else {
            DEFAULT_RELEASE_AGE_SECS
        };
        Self {
            policy: policy.unwrap_or_default(),
            age_choice,
            custom_secs,
        }
    }

    const fn step_scope(&mut self) {
        self.policy = match self.policy {
            crate::release_age_config::ReleaseAgePolicy::Direct => {
                crate::release_age_config::ReleaseAgePolicy::Strict
            }
            crate::release_age_config::ReleaseAgePolicy::Strict => {
                crate::release_age_config::ReleaseAgePolicy::Direct
            }
        };
    }

    const fn step_age(&mut self, step: SelectionStep) {
        self.age_choice = self.age_choice.step(step);
    }
}

pub(in crate::commands::config) async fn run_release_age_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let selection = if let Some(value) = set {
        parse_release_age_selection(value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config release-age requires a TTY; use `--set default|off|0|<N>h|<N>d` instead"
                    .to_string(),
            ));
        }

        let current = read_release_age_override(config_path)?;
        println!();
        println!("  current: {}", format_current_release_age(current).cyan());
        let preset: &str =
            cliclack::select("How long should LPM wait before allowing newly published packages?")
                .item("default", "Default (1 day)", "recommended")
                .item("cautious", "Cautious (3 days)", "stricter")
                .item("off", "Off", "NOT recommended — disables the cooldown")
                .item("custom", "Custom", "enter 12h / 7d / 0")
                .initial_value(release_age_initial_choice(current))
                .interact()
                .map_err(prompt_err)?;

        match preset {
            "default" => ReleaseAgeSelection::Default,
            "cautious" => ReleaseAgeSelection::Seconds(CAUTIOUS_RELEASE_AGE_SECS),
            "off" => ReleaseAgeSelection::Seconds(0),
            "custom" => ReleaseAgeSelection::Seconds(prompt_custom_release_age(
                current.unwrap_or(DEFAULT_RELEASE_AGE_SECS),
            )?),
            _ => unreachable!("release-age select returned unexpected preset"),
        }
    };

    let requested_secs = release_age_requested_secs(selection);
    let requested_policy = if set.is_none() && requested_secs > 0 {
        Some(prompt_release_age_policy(config_path)?)
    } else {
        None
    };
    let command_hint = release_age_command_hint(selection);
    let persisted = persist_release_age_selection(
        config_path,
        selection,
        requested_policy,
        json_output,
        &command_hint,
    )
    .await?;
    announce_release_age_set(persisted, json_output);
    Ok(())
}

pub(in crate::commands::config) async fn run_release_age_configuration_wizard(
    config_path: &std::path::Path,
) -> Result<(), LpmError> {
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "release age configuration requires a TTY; use `lpm config release-age --set <duration>` and `lpm config release-age-policy --set direct|strict` instead"
                .to_string(),
        ));
    }

    let initial = read_release_age_editor_settings(config_path)?;
    let mut term = Term::stderr();
    let mut selected = run_release_age_editor(&mut term, initial).map_err(prompt_err)?;
    if selected.age_choice == ReleaseAgeChoice::Custom {
        selected.custom_secs = prompt_custom_release_age(selected.custom_secs)?;
    }

    let selection = selected.age_choice.selection(selected.custom_secs);
    let persisted = persist_release_age_selection(
        config_path,
        selection,
        Some(selected.policy),
        false,
        &release_age_command_hint(selection),
    )
    .await?;
    announce_release_age_configuration_set(persisted, selected.policy);
    Ok(())
}

fn read_release_age_editor_settings(
    config_path: &std::path::Path,
) -> Result<ReleaseAgeEditorSettings, LpmError> {
    let global = GlobalConfig::from_value(read_config(config_path)?)?;
    let age = global.get_u64(RELEASE_AGE_KEY);
    let policy = global
        .get_str(RELEASE_AGE_POLICY_KEY)
        .map(|raw| crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, raw))
        .transpose()?;
    Ok(ReleaseAgeEditorSettings::from_overrides(age, policy))
}

fn run_release_age_editor(
    term: &mut Term,
    initial: ReleaseAgeEditorSettings,
) -> io::Result<ReleaseAgeEditorSettings> {
    super::editor::run(term, |term| interact_release_age_editor(term, initial))
}

fn interact_release_age_editor(
    term: &mut Term,
    mut settings: ReleaseAgeEditorSettings,
) -> io::Result<ReleaseAgeEditorSettings> {
    let mut cursor = 0;
    let mut previous_line_count = 0;
    loop {
        let frame = format_release_age_editor_frame(settings, cursor);
        super::editor::draw_frame(term, &frame, &mut previous_line_count)?;

        match term.read_key()? {
            Key::ArrowUp | Key::ArrowDown | Key::Char('j') | Key::Char('k') => cursor ^= 1,
            Key::ArrowLeft | Key::Char('h') => {
                if cursor == 0 {
                    settings.step_scope();
                } else {
                    settings.step_age(SelectionStep::Previous);
                }
            }
            Key::ArrowRight | Key::Char('l') | Key::Char(' ') => {
                if cursor == 0 {
                    settings.step_scope();
                } else {
                    settings.step_age(SelectionStep::Next);
                }
            }
            Key::Enter => return Ok(settings),
            Key::Escape | Key::CtrlC => return Err(io::ErrorKind::Interrupted.into()),
            _ => {}
        }
    }
}

fn format_release_age_editor_frame(settings: ReleaseAgeEditorSettings, cursor: usize) -> String {
    let mut frame = String::with_capacity(800);
    frame.push_str(&format!(
        "◆  {}\n",
        RELEASE_AGE_GUIDED_MENU_LABEL.cyan().bold()
    ));
    frame.push_str(&format!("│  {}\n", RELEASE_AGE_EDITOR_HELP.dimmed()));
    frame.push_str("│\n");
    push_release_age_editor_row(
        &mut frame,
        cursor == 0,
        "Release-age scope",
        "Apply the release-age cooldown to which dependencies?",
        &format_release_age_policy_options(settings.policy),
    );
    frame.push_str("│\n");
    push_release_age_editor_row(
        &mut frame,
        cursor == 1,
        "Minimum release age",
        "How long should LPM wait before allowing newly published packages?",
        &format_release_age_options(settings.age_choice),
    );
    frame.push_str("└\n");
    frame
}

fn push_release_age_editor_row(
    frame: &mut String,
    active: bool,
    title: &str,
    detail: &str,
    options: &str,
) {
    let marker = if active {
        "›".cyan().bold()
    } else {
        " ".to_string()
    };
    let title = if active {
        title.bold()
    } else {
        title.to_string()
    };
    frame.push_str(&format!("│  {marker} {title}\n"));
    frame.push_str(&format!("│    {}\n", detail.dimmed()));
    frame.push_str(&format!("│    {options}\n"));
}

fn format_release_age_policy_options(
    policy: crate::release_age_config::ReleaseAgePolicy,
) -> String {
    let mut rendered = String::with_capacity(150);
    push_release_age_option(
        &mut rendered,
        policy == crate::release_age_config::ReleaseAgePolicy::Direct,
        "direct dependencies (default; fastest normal installs)",
    );
    push_release_age_option(
        &mut rendered,
        policy == crate::release_age_config::ReleaseAgePolicy::Strict,
        "direct and transitive dependencies",
    );
    rendered
}

fn format_release_age_options(choice: ReleaseAgeChoice) -> String {
    let mut rendered = String::with_capacity(130);
    for (candidate, label) in [
        (ReleaseAgeChoice::Default, "Default (1 day) (recommended)"),
        (ReleaseAgeChoice::Cautious, "Cautious (3 days)"),
        (ReleaseAgeChoice::Off, "Off"),
        (ReleaseAgeChoice::Custom, "Custom"),
    ] {
        push_release_age_option(&mut rendered, choice == candidate, label);
    }
    rendered
}

fn push_release_age_option(rendered: &mut String, selected: bool, label: &str) {
    if !rendered.is_empty() {
        rendered.push_str("  ");
    }
    if selected {
        rendered.push_str(&format!("{} {}", "●".cyan(), label.bold()));
    } else {
        rendered.push_str(&format!("○ {label}"));
    }
}

fn prompt_custom_release_age(default_secs: u64) -> Result<u64, LpmError> {
    let default_input = format_release_age_cli_value(default_secs);
    let duration: String = cliclack::input("Minimum release age")
        .default_input(&default_input)
        .placeholder("1d, 12h, 0")
        .validate(|input: &String| {
            crate::release_age_config::parse_duration(input)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .interact()
        .map_err(prompt_err)?;
    crate::release_age_config::parse_duration(&duration)
}

const fn release_age_requested_secs(selection: ReleaseAgeSelection) -> u64 {
    match selection {
        ReleaseAgeSelection::Default => DEFAULT_RELEASE_AGE_SECS,
        ReleaseAgeSelection::Seconds(secs) => secs,
    }
}

fn release_age_command_hint(selection: ReleaseAgeSelection) -> String {
    match selection {
        ReleaseAgeSelection::Default => "lpm config release-age --set default".to_string(),
        ReleaseAgeSelection::Seconds(0) => "lpm config release-age --set 0".to_string(),
        ReleaseAgeSelection::Seconds(secs) => format!(
            "lpm config release-age --set {}",
            format_release_age_cli_value(secs)
        ),
    }
}

fn parse_release_age_selection(input: &str) -> Result<ReleaseAgeSelection, LpmError> {
    match input {
        "default" => Ok(ReleaseAgeSelection::Default),
        "off" => Ok(ReleaseAgeSelection::Seconds(0)),
        other => crate::release_age_config::parse_duration(other).map(ReleaseAgeSelection::Seconds),
    }
}

pub(in crate::commands::config) fn read_release_age_override(
    config_path: &std::path::Path,
) -> Result<Option<u64>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    Ok(GlobalConfig { table }.get_u64(RELEASE_AGE_KEY))
}

pub(in crate::commands::config) fn read_release_age_policy_override(
    config_path: &std::path::Path,
) -> Result<Option<crate::release_age_config::ReleaseAgePolicy>, LpmError> {
    let cfg = read_config(config_path)?;
    let table = match cfg {
        toml::Value::Table(table) => table,
        _ => return Ok(None),
    };
    let Some(raw) = table.get(RELEASE_AGE_POLICY_KEY).and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    Ok(Some(crate::release_age_config::ReleaseAgePolicy::parse(
        RELEASE_AGE_POLICY_KEY,
        raw,
    )?))
}

pub(in crate::commands::config) fn prompt_release_age_policy(
    config_path: &std::path::Path,
) -> Result<crate::release_age_config::ReleaseAgePolicy, LpmError> {
    let current = read_release_age_policy_override(config_path)?.unwrap_or_default();
    let choice: &str = cliclack::select("Apply the release-age cooldown to which dependencies?")
        .item(
            "direct",
            "direct dependencies",
            "default; fastest normal installs",
        )
        .item(
            "strict",
            "direct and transitive dependencies",
            "stricter supply-chain posture",
        )
        .initial_value(current.as_str())
        .interact()
        .map_err(prompt_err)?;
    crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, choice)
}

pub(in crate::commands::config) async fn persist_release_age_selection(
    config_path: &std::path::Path,
    selection: ReleaseAgeSelection,
    requested_policy: Option<crate::release_age_config::ReleaseAgePolicy>,
    json_output: bool,
    command_hint: &str,
) -> Result<Option<u64>, LpmError> {
    let requested_secs = release_age_requested_secs(selection);
    update_config(config_path, |config| {
        crate::security_floor::reject_looser_release_age_write(config, requested_secs)?;
        crate::security_approval::authorize_persistent_release_age(
            requested_secs,
            json_output,
            command_hint,
        )?;
        if let Some(policy) = requested_policy {
            crate::security_floor::reject_looser_release_age_policy_write(config, policy)?;
            crate::security_approval::authorize_persistent_release_age_policy(
                policy,
                json_output,
                &format!("lpm config release-age-policy --set {}", policy.as_str()),
            )?;
        }

        let top = config.table_mut();
        let persisted = match selection {
            ReleaseAgeSelection::Default => {
                top.remove(RELEASE_AGE_KEY);
                None
            }
            ReleaseAgeSelection::Seconds(secs) => {
                top.insert(
                    RELEASE_AGE_KEY.to_string(),
                    toml::Value::String(secs.to_string()),
                );
                Some(secs)
            }
        };
        if let Some(policy) = requested_policy {
            top.insert(
                RELEASE_AGE_POLICY_KEY.to_string(),
                toml::Value::String(policy.as_str().to_string()),
            );
        }
        Ok((persisted, true))
    })
    .await
}

pub(in crate::commands::config) async fn run_release_age_policy_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let policy = if let Some(value) = set {
        crate::release_age_config::ReleaseAgePolicy::parse(RELEASE_AGE_POLICY_KEY, value)?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config release-age-policy requires a TTY; use `--set direct|strict` instead"
                    .to_string(),
            ));
        }
        prompt_release_age_policy(config_path)?
    };

    update_config(config_path, |config| {
        crate::security_floor::reject_looser_release_age_policy_write(config, policy)?;
        crate::security_approval::authorize_persistent_release_age_policy(
            policy,
            json_output,
            &format!("lpm config release-age-policy --set {}", policy.as_str()),
        )?;
        let table = config.table_mut();
        table.insert(
            RELEASE_AGE_POLICY_KEY.to_string(),
            toml::Value::String(policy.as_str().to_string()),
        );
        Ok(((), true))
    })
    .await?;
    announce_release_age_policy_set(policy, json_output);
    Ok(())
}

pub(in crate::commands::config) fn format_release_age_cli_value(secs: u64) -> String {
    if secs == 0 {
        return "0".to_string();
    }
    if secs.is_multiple_of(86400) {
        return format!("{}d", secs / 86400);
    }
    if secs.is_multiple_of(3600) {
        return format!("{}h", secs / 3600);
    }
    secs.to_string()
}

pub(in crate::commands::config) fn format_current_release_age(current: Option<u64>) -> String {
    match current {
        None => "default (1d)".to_string(),
        Some(0) => "off".to_string(),
        Some(secs) if secs == DEFAULT_RELEASE_AGE_SECS => "1d (explicit override)".to_string(),
        Some(secs) => format_release_age_cli_value(secs),
    }
}

pub(in crate::commands::config) fn release_age_initial_choice(
    current: Option<u64>,
) -> &'static str {
    ReleaseAgeChoice::from_override(current).initial_value()
}

fn announce_release_age_configuration_set(
    value: Option<u64>,
    policy: crate::release_age_config::ReleaseAgePolicy,
) {
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Saved release age configuration: scope = {}, minimum = {}",
        install_ui::bold(policy.as_str()),
        install_ui::bold(&format_current_release_age(value)),
    ));
}

pub(in crate::commands::config) fn announce_release_age_set(value: Option<u64>, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                RELEASE_AGE_KEY: value,
            }))
            .unwrap()
        );
        return;
    }

    match value {
        None => install_ui::done("Using default minimum release age (1d)"),
        Some(0) => install_ui::done("Set minimum release age = off"),
        Some(secs) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Set minimum release age = {}",
            install_ui::bold(&format_release_age_cli_value(secs)),
        )),
    }
}

pub(in crate::commands::config) fn announce_release_age_policy_set(
    policy: crate::release_age_config::ReleaseAgePolicy,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                RELEASE_AGE_POLICY_KEY: policy.as_str(),
            }))
            .unwrap()
        );
        return;
    }
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Set release-age-policy = {}",
        install_ui::bold(policy.as_str()),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_editor_frame_contains_scope_and_minimum_age_controls() {
        let frame = format_release_age_editor_frame(
            ReleaseAgeEditorSettings::from_overrides(
                None,
                Some(crate::release_age_config::ReleaseAgePolicy::Direct),
            ),
            0,
        );
        let plain = console::strip_ansi_codes(&frame);

        assert!(plain.contains("Release age configuration"));
        assert!(plain.contains("Release-age scope"));
        assert!(plain.contains("direct and transitive dependencies"));
        assert!(plain.contains("Minimum release age"));
        assert!(plain.contains("● Default (1 day) (recommended)"));
        assert!(plain.contains("○ Cautious (3 days)"));
        assert!(plain.contains("○ Off"));
        assert!(plain.contains("○ Custom"));
    }

    #[test]
    fn grouped_editor_preserves_custom_release_age_for_the_input_default() {
        let settings = ReleaseAgeEditorSettings::from_overrides(
            Some(12 * 60 * 60),
            Some(crate::release_age_config::ReleaseAgePolicy::Strict),
        );

        assert_eq!(
            settings,
            ReleaseAgeEditorSettings {
                policy: crate::release_age_config::ReleaseAgePolicy::Strict,
                age_choice: ReleaseAgeChoice::Custom,
                custom_secs: 12 * 60 * 60,
            }
        );
    }

    #[test]
    fn grouped_editor_age_choices_wrap_in_both_directions() {
        assert_eq!(
            [
                ReleaseAgeChoice::Default.step(SelectionStep::Previous),
                ReleaseAgeChoice::Custom.step(SelectionStep::Next),
            ],
            [ReleaseAgeChoice::Custom, ReleaseAgeChoice::Default]
        );
    }
}
