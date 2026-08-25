use super::prelude::*;
use crate::lpm_insights_config::FETCH_LPM_SECURITY_INSIGHTS_KEY;
use crate::lpm_skills_config::{
    AUTO_INSTALL_LPM_SKILLS_KEY, LEGACY_NO_SKILLS_KEY, LpmSkillsPreference,
};
use console::{Key, Term, measure_text_width};
use std::io::{self, Write};

const LPM_DEV_EDITOR_PROMPT: &str = "LPM.dev settings";
const LPM_DEV_EDITOR_HELP: &str = "Use ↑/↓ to move, ←/→ to change, Enter to save, Esc to cancel.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LpmDevSettings {
    package_skills: bool,
    security_insights: bool,
}

pub(in crate::commands::config) async fn run_lpm_dev_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if set.is_some() {
        return Err(LpmError::Registry(
            "lpm config lpm-dev is a combined interactive editor; use `lpm config lpm-skills --set true|false` or `lpm config lpm-insights --set true|false` for scripts"
                .to_string(),
        ));
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config lpm-dev requires a TTY; use the focused `lpm-skills` or `lpm-insights` setters instead"
                .to_string(),
        ));
    }

    let initial = read_lpm_dev_settings(config_path)?;
    let mut term = Term::stderr();
    let selected = run_lpm_dev_editor(&mut term, initial).map_err(prompt_err)?;
    persist_lpm_dev_settings(config_path, selected).await?;
    install_ui::done("Saved LPM.dev settings");
    Ok(())
}

pub(in crate::commands::config) async fn run_lpm_insights_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value).map_err(|message| {
            LpmError::Registry(format!("`{FETCH_LPM_SECURITY_INSIGHTS_KEY}` {message}"))
        })?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config lpm-insights requires a TTY; use `--set true|false` instead"
                    .to_string(),
            ));
        }
        let current = read_fetch_lpm_security_insights(config_path)?;
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let selected: &str = cliclack::select(
            "Fetch install-time LPM.dev security insights for @lpm.dev/* packages?",
        )
        .item(
            "true",
            "enabled",
            "default; enrich the install summary with server-side findings",
        )
        .item(
            "false",
            "disabled",
            "show local analysis only; do not fetch summary enrichment",
        )
        .initial_value(if current { "true" } else { "false" })
        .interact()
        .map_err(prompt_err)?;
        parse_config_bool(selected).map_err(|message| {
            LpmError::Registry(format!("`{FETCH_LPM_SECURITY_INSIGHTS_KEY}` {message}"))
        })?
    };

    persist_bool(config_path, FETCH_LPM_SECURITY_INSIGHTS_KEY, enabled).await?;
    announce_bool_set(FETCH_LPM_SECURITY_INSIGHTS_KEY, enabled, json_output);
    Ok(())
}

pub(in crate::commands::config) fn read_fetch_lpm_security_insights(
    config_path: &std::path::Path,
) -> Result<bool, LpmError> {
    let config = read_config(config_path)?;
    crate::lpm_insights_config::read_fetch_lpm_security_insights(&GlobalConfig::from_value(config)?)
}

fn read_lpm_dev_settings(config_path: &std::path::Path) -> Result<LpmDevSettings, LpmError> {
    let config = read_config(config_path)?;
    let global = GlobalConfig::from_value(config)?;
    Ok(LpmDevSettings {
        package_skills: LpmSkillsPreference::Config.resolve(&global)?,
        security_insights: crate::lpm_insights_config::read_fetch_lpm_security_insights(&global)?,
    })
}

async fn persist_lpm_dev_settings(
    config_path: &std::path::Path,
    settings: LpmDevSettings,
) -> Result<(), LpmError> {
    update_config(config_path, |config| {
        let table = config.table_mut();
        table.remove(LEGACY_NO_SKILLS_KEY);
        table.insert(
            AUTO_INSTALL_LPM_SKILLS_KEY.to_string(),
            toml::Value::Boolean(settings.package_skills),
        );
        table.insert(
            FETCH_LPM_SECURITY_INSIGHTS_KEY.to_string(),
            toml::Value::Boolean(settings.security_insights),
        );
        Ok(((), true))
    })
    .await
}

fn run_lpm_dev_editor(term: &mut Term, initial: LpmDevSettings) -> io::Result<LpmDevSettings> {
    if !term.is_term() {
        return Err(io::ErrorKind::NotConnected.into());
    }
    term.hide_cursor()?;
    let result = interact_lpm_dev_editor(term, initial);
    let show_cursor_result = term.show_cursor();
    match (result, show_cursor_result) {
        (Ok(settings), Ok(())) => Ok(settings),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn interact_lpm_dev_editor(
    term: &mut Term,
    mut settings: LpmDevSettings,
) -> io::Result<LpmDevSettings> {
    let mut cursor = 0;
    let mut previous_line_count = 0;
    loop {
        let frame = format_lpm_dev_editor_frame(settings, cursor);
        if previous_line_count > 0 {
            term.clear_last_lines(previous_line_count)?;
        }
        term.write_all(frame.as_bytes())?;
        term.flush()?;
        previous_line_count = rendered_line_count(&frame, usize::from(term.size().1).max(1));

        match term.read_key()? {
            Key::ArrowUp | Key::ArrowDown | Key::Char('j') | Key::Char('k') => cursor ^= 1,
            Key::ArrowLeft | Key::ArrowRight | Key::Char('h') | Key::Char('l') | Key::Char(' ') => {
                if cursor == 0 {
                    settings.package_skills = !settings.package_skills;
                } else {
                    settings.security_insights = !settings.security_insights;
                }
            }
            Key::Enter => return Ok(settings),
            Key::Escape | Key::CtrlC => return Err(io::ErrorKind::Interrupted.into()),
            _ => {}
        }
    }
}

fn format_lpm_dev_editor_frame(settings: LpmDevSettings, cursor: usize) -> String {
    let rows = [
        (
            "LPM.dev package skills",
            "Auto-install package-published skills from @lpm.dev/* packages?",
            settings.package_skills,
        ),
        (
            "Fetch LPM Registry Insights",
            "At install time, use registry behavioral tags and lifecycle-script data. Audits add AI findings and vulnerabilities.",
            settings.security_insights,
        ),
    ];
    let mut frame = String::with_capacity(720);
    frame.push_str(&format!("◆  {}\n", LPM_DEV_EDITOR_PROMPT.cyan().bold()));
    frame.push_str(&format!("│  {}\n", LPM_DEV_EDITOR_HELP.dimmed()));
    frame.push_str("│\n");
    for (index, (title, detail, enabled)) in rows.into_iter().enumerate() {
        let active = index == cursor;
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
        frame.push_str(&format!("│    {}\n", format_bool_options(enabled)));
        if index == 0 {
            frame.push_str("│\n");
        }
    }
    frame.push_str("└\n");
    frame
}

fn format_bool_options(enabled: bool) -> String {
    if enabled {
        format!("{} {}  ○ Disabled", "●".cyan(), "Enabled".bold())
    } else {
        format!("○ Enabled  {} {}", "●".cyan(), "Disabled".bold())
    }
}

fn rendered_line_count(frame: &str, terminal_width: usize) -> usize {
    let terminal_width = terminal_width.max(1);
    frame
        .lines()
        .map(|line| {
            let width = measure_text_width(line);
            width.saturating_sub(1) / terminal_width + 1
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_editor_frame_contains_both_lpm_dev_controls() {
        let frame = format_lpm_dev_editor_frame(
            LpmDevSettings {
                package_skills: true,
                security_insights: false,
            },
            0,
        );
        let plain = console::strip_ansi_codes(&frame);
        assert!(plain.contains("LPM.dev package skills"));
        assert!(plain.contains("Fetch LPM Registry Insights"));
        assert!(plain.contains("Audits add AI findings and vulnerabilities"));
        assert!(plain.contains("● Enabled"));
        assert!(plain.contains("● Disabled"));
    }

    #[tokio::test]
    async fn grouped_save_writes_both_booleans_and_removes_legacy_skills_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "noSkills = true\nregistry = \"https://example.test\"\n",
        )
        .unwrap();

        persist_lpm_dev_settings(
            &path,
            LpmDevSettings {
                package_skills: true,
                security_insights: false,
            },
        )
        .await
        .unwrap();

        let config = read_config(&path).unwrap();
        assert_eq!(
            config.get(AUTO_INSTALL_LPM_SKILLS_KEY),
            Some(&toml::Value::Boolean(true))
        );
        assert_eq!(
            config.get(FETCH_LPM_SECURITY_INSIGHTS_KEY),
            Some(&toml::Value::Boolean(false))
        );
        assert!(config.get(LEGACY_NO_SKILLS_KEY).is_none());
        assert_eq!(
            config.get("registry").and_then(toml::Value::as_str),
            Some("https://example.test")
        );
    }
}
