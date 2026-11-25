//! How much of a release's `skills/<name>/` directories LPM.dev reviews.
//! LPM.dev approves a directory only after reviewing all of its files, and
//! installs link an LPM.dev package's directory only once approved, so a
//! directory review leaves out publishes but never links from LPM.dev.

/// The most a `skills/<name>/` directory may hold, in bytes, for LPM.dev
/// to review it.
pub const MAX_REVIEWED_SKILL_DIRECTORY_SIZE: u64 = 128 * 1024;

/// The most a release's reviewed `skills/<name>/` directories may hold
/// together, in bytes.
pub const MAX_REVIEWED_SKILL_DIRECTORIES_SIZE: u64 = 512 * 1024;

/// Why LPM.dev leaves a skill directory that passes every check unreviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreviewed {
    /// The directory holds more than [`MAX_REVIEWED_SKILL_DIRECTORY_SIZE`].
    TooLarge { size: u64 },
    /// With the directories before it, in name order, it would take the
    /// release past [`MAX_REVIEWED_SKILL_DIRECTORIES_SIZE`].
    ReleaseFull { size: u64 },
}

impl Unreviewed {
    /// The reason as one line about `skills/<name>/`.
    pub fn message(self, name: &str) -> String {
        match self {
            Self::TooLarge { size } => format!(
                "skills/{name}/: holds {size} bytes, more than the {} KiB LPM.dev reviews in a skill directory, so installs from LPM.dev won't link it",
                MAX_REVIEWED_SKILL_DIRECTORY_SIZE / 1024
            ),
            Self::ReleaseFull { size } => format!(
                "skills/{name}/: its {size} bytes don't fit the {} KiB LPM.dev reviews across a release's skill directories, so installs from LPM.dev won't link it",
                MAX_REVIEWED_SKILL_DIRECTORIES_SIZE / 1024
            ),
        }
    }
}

/// Which of a release's skill directories that pass every check LPM.dev
/// reviews, given as `(name, size in bytes)`: in name order, each holding at
/// most [`MAX_REVIEWED_SKILL_DIRECTORY_SIZE`] while the reviewed ones stay
/// within [`MAX_REVIEWED_SKILL_DIRECTORIES_SIZE`] together, so a smaller
/// directory after one that doesn't fit is still reviewed. Returns each
/// directory, in name order, with why it isn't reviewed.
pub fn review_plan<'a>(
    directories: impl IntoIterator<Item = (&'a str, u64)>,
) -> Vec<(&'a str, Option<Unreviewed>)> {
    let mut ordered: Vec<(&str, u64)> = directories.into_iter().collect();
    ordered.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut reviewed = 0u64;
    ordered
        .into_iter()
        .map(|(name, size)| {
            let outcome = if size > MAX_REVIEWED_SKILL_DIRECTORY_SIZE {
                Some(Unreviewed::TooLarge { size })
            } else if reviewed.saturating_add(size) > MAX_REVIEWED_SKILL_DIRECTORIES_SIZE {
                Some(Unreviewed::ReleaseFull { size })
            } else {
                reviewed += size;
                None
            };
            (name, outcome)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    #[test]
    fn a_directory_over_the_per_directory_cap_is_left_unreviewed() {
        let plan = review_plan([
            ("big", MAX_REVIEWED_SKILL_DIRECTORY_SIZE + 1),
            ("exact", MAX_REVIEWED_SKILL_DIRECTORY_SIZE),
        ]);

        assert_eq!(
            plan,
            [
                (
                    "big",
                    Some(Unreviewed::TooLarge {
                        size: MAX_REVIEWED_SKILL_DIRECTORY_SIZE + 1
                    })
                ),
                ("exact", None),
            ]
        );
    }

    #[test]
    fn directories_are_reviewed_in_name_order_while_the_release_has_room() {
        let plan = review_plan([
            ("f", 50 * KIB),
            ("a", 100 * KIB),
            ("g", 12 * KIB),
            ("b", 100 * KIB),
            ("c", 100 * KIB),
            ("d", 100 * KIB),
            ("e", 100 * KIB),
        ]);

        let unreviewed: Vec<_> = plan
            .iter()
            .filter_map(|(name, outcome)| outcome.map(|outcome| (*name, outcome)))
            .collect();
        assert_eq!(
            unreviewed,
            [("f", Unreviewed::ReleaseFull { size: 50 * KIB })]
        );
        assert_eq!(
            plan.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            ["a", "b", "c", "d", "e", "f", "g"]
        );
    }

    #[test]
    fn an_oversized_directory_takes_none_of_the_release_budget() {
        let full = MAX_REVIEWED_SKILL_DIRECTORY_SIZE;
        let plan = review_plan([
            ("a-big", full * 5),
            ("b1", full),
            ("b2", full),
            ("b3", full),
            ("b4", full),
            ("c", 1),
        ]);

        assert!(matches!(plan[0].1, Some(Unreviewed::TooLarge { .. })));
        assert!(plan[1..5].iter().all(|(_, outcome)| outcome.is_none()));
        assert_eq!(plan[5], ("c", Some(Unreviewed::ReleaseFull { size: 1 })));
    }

    #[test]
    fn messages_name_the_directory_its_size_and_the_cap() {
        assert_eq!(
            Unreviewed::TooLarge { size: 200_000 }.message("guide"),
            "skills/guide/: holds 200000 bytes, more than the 128 KiB LPM.dev reviews in a skill directory, so installs from LPM.dev won't link it"
        );
        assert!(
            Unreviewed::ReleaseFull { size: 9 }
                .message("guide")
                .contains("512 KiB")
        );
    }
}
