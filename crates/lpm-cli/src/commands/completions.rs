//! Shell completion scripts for the public CLI surface.

use clap::{Command, CommandFactory};
use clap_complete::Shell;
use lpm_common::LpmError;
use std::io::{self, Write};

pub fn run(shell: Shell) -> Result<(), LpmError> {
    match write_script(shell, &mut io::stdout().lock()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_script(shell: Shell, output: &mut impl Write) -> io::Result<()> {
    let mut source = crate::Cli::command();
    source.build();
    let mut command = public_command(&source);
    // Some shell generators panic on write errors, even through try_generate.
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut command, "lpm", &mut script);
    output.write_all(&script)?;
    output.flush()
}

fn public_command(source: &Command) -> Command {
    let visible_ids: std::collections::HashSet<_> = source
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .map(|arg| arg.get_id())
        .collect();
    let groups = source.get_groups().map(|group| {
        group.clone().arg(clap::builder::Resettable::Reset).args(
            group
                .get_args()
                .filter(|id| visible_ids.contains(id))
                .cloned(),
        )
    });
    let mut command = Command::new(source.get_name().to_owned())
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .allow_external_subcommands(source.is_allow_external_subcommands_set())
        .allow_missing_positional(source.is_allow_missing_positional_set())
        .args(
            source
                .get_arguments()
                .filter(|arg| !arg.is_hide_set())
                .cloned(),
        )
        .groups(groups)
        .visible_aliases(source.get_visible_aliases().map(str::to_owned))
        .subcommands(
            source
                .get_subcommands()
                .filter(|child| !child.is_hide_set())
                .map(public_command),
        );
    if let Some(about) = source.get_about() {
        command = command.about(about.clone());
    }
    if let Some(about) = source.get_long_about() {
        command = command.long_about(about.clone());
    }
    if let Some(flag) = source.get_short_flag() {
        command = command.short_flag(flag);
    }
    if let Some(flag) = source.get_long_flag() {
        command = command.long_flag(flag.to_owned());
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailedOutput {
        fail_flush: bool,
    }
    impl Write for FailedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_flush {
                Ok(bytes.len())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test writer",
                ))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test flush",
            ))
        }
    }

    #[test]
    fn completion_output_propagates_write_and_flush_errors_without_panicking() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            for fail_flush in [false, true] {
                let error = write_script(shell, &mut FailedOutput { fail_flush }).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
        }
    }

    #[test]
    fn public_schema_retains_aliases_value_parsers_and_visible_conflicts() {
        let mut original = Command::new("example")
            .arg(clap::Arg::new("secret").long("secret").hide(true))
            .arg(
                clap::Arg::new("json")
                    .long("json")
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with("text"),
            )
            .arg(
                clap::Arg::new("text")
                    .long("text")
                    .action(clap::ArgAction::SetTrue),
            )
            .subcommand(
                Command::new("visible").visible_alias("alias").arg(
                    clap::Arg::new("mode")
                        .long("mode")
                        .value_parser(["fast", "full"]),
                ),
            )
            .subcommand(Command::new("internal").hide(true));
        original.build();
        let mut public = public_command(&original);
        public.build();
        assert!(public.find_subcommand("alias").is_some());
        assert!(public.find_subcommand("internal").is_none());
        assert!(!public.get_arguments().any(|arg| arg.get_id() == "secret"));
        let json = public
            .get_arguments()
            .find(|arg| arg.get_id() == "json")
            .unwrap();
        assert_eq!(public.get_arg_conflicts_with(json)[0].get_id(), "text");
        let child = public.find_subcommand("visible").unwrap();
        let mode = child
            .get_arguments()
            .find(|arg| arg.get_id() == "mode")
            .unwrap();
        assert_eq!(
            mode.get_value_parser()
                .possible_values()
                .unwrap()
                .map(|v| v.get_name().to_owned())
                .collect::<Vec<_>>(),
            ["fast", "full"]
        );
    }
}
