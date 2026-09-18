const MAX_DIFF_BYTES: usize = 16 * 1024;
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_INPUT_LINES: usize = 2048;
const CONTEXT_LINES: usize = 3;

pub(super) fn bounded_diff(current: &str, candidate: &str) -> String {
    if current == candidate {
        return String::new();
    }
    let mut prefix_bytes = 0;
    let mut prefix_lines: usize = 0;
    for (left, right) in current
        .split_inclusive('\n')
        .zip(candidate.split_inclusive('\n'))
    {
        if left != right {
            break;
        }
        prefix_bytes += left.len();
        prefix_lines += 1;
    }
    let prefix_context: usize = current[..prefix_bytes]
        .split_inclusive('\n')
        .rev()
        .take(CONTEXT_LINES)
        .map(str::len)
        .sum();
    let start = prefix_bytes - prefix_context;
    let suffix_bytes: usize = current[prefix_bytes..]
        .split_inclusive('\n')
        .rev()
        .zip(candidate[prefix_bytes..].split_inclusive('\n').rev())
        .take_while(|(left, right)| left == right)
        .map(|(line, _)| line.len())
        .sum();
    let suffix_context: usize = current[current.len() - suffix_bytes..]
        .split_inclusive('\n')
        .take(CONTEXT_LINES)
        .map(str::len)
        .sum();
    let use_complete_inputs = current.len().saturating_add(candidate.len()) <= MAX_INPUT_BYTES
        && current
            .lines()
            .count()
            .saturating_add(candidate.lines().count())
            <= MAX_INPUT_LINES;
    let (left, right, excerpt) = if use_complete_inputs {
        (current, candidate, false)
    } else {
        (
            &current[start..current.len() - suffix_bytes + suffix_context],
            &candidate[start..candidate.len() - suffix_bytes + suffix_context],
            start != 0 || suffix_bytes > suffix_context,
        )
    };
    if left.len().saturating_add(right.len()) > MAX_INPUT_BYTES
        || left.lines().count().saturating_add(right.lines().count()) > MAX_INPUT_LINES
    {
        return format!(
            "Diff omitted: changed region exceeds {MAX_INPUT_BYTES} bytes or {MAX_INPUT_LINES} lines. Original: {} bytes; updated: {} bytes. Inspect the source before applying.\n",
            current.len(),
            candidate.len()
        );
    }
    let mut patch = if excerpt {
        format!(
            "Excerpt starting at line {} (hunk line numbers are relative):\n",
            prefix_lines.saturating_sub(CONTEXT_LINES) + 1
        )
    } else {
        String::new()
    };
    patch.push_str(&diffy::create_patch(left, right).to_string());
    if patch.len() > MAX_DIFF_BYTES {
        const NOTICE: &str = "\n… diff truncated at 16384 bytes\n";
        let mut end = MAX_DIFF_BYTES - NOTICE.len();
        while !patch.is_char_boundary(end) {
            end -= 1;
        }
        patch.truncate(end);
        patch.push_str(NOTICE);
    }
    patch
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_diff_replacement_has_a_bounded_summary() {
        let current = "old line\n".repeat(3000);
        let candidate = "new line\n".repeat(3000);
        let diff = bounded_diff(&current, &candidate);
        assert!(
            diff.starts_with("Diff omitted:"),
            "{}",
            &diff[..diff.len().min(200)]
        );
        assert!(diff.len() < 1024);
    }

    #[test]
    fn large_mostly_equal_diffs_keep_small_edits_at_every_position() {
        let lines: Vec<_> = (0..10_000)
            .map(|i| format!("unchanged line {i}\n"))
            .collect();
        let current = lines.concat();
        assert!(bounded_diff(&current, &current).is_empty());
        for index in [0, 5000, 9999] {
            let mut candidate = lines.clone();
            candidate[index] = "replacement instruction\n".into();
            let diff = bounded_diff(&current, &candidate.concat());
            let expected_start = index.saturating_sub(3) + 1;
            assert!(
                diff.starts_with(&format!("Excerpt starting at line {expected_start} ")),
                "{diff}"
            );
            assert!(diff.contains("+replacement instruction"), "{diff}");
            assert!(diff.contains(&format!("-unchanged line {index}")), "{diff}");
            assert!(diff.len() < 2048);
        }
    }

    #[test]
    fn giant_unicode_line_diff_has_a_bounded_summary() {
        let diff = bounded_diff(&"😀".repeat(20000), &"界".repeat(25000));
        assert!(diff.starts_with("Diff omitted:"));
        assert!(diff.len() < 1024);
    }
    #[test]
    fn unicode_patch_output_stays_within_the_display_budget() {
        let current = format!("{}\n", "界".repeat(90)).repeat(90);
        let candidate = format!("{}\n", "語".repeat(90)).repeat(90);
        let diff = bounded_diff(&current, &candidate);
        assert!(diff.len() <= MAX_DIFF_BYTES);
        assert!(diff.ends_with("… diff truncated at 16384 bytes\n"));
    }

    #[test]
    fn small_diffs_preserve_complete_patch_line_numbers() {
        for (current, candidate) in [
            ("a\nb\nc\nd\ne\nf\n", "a\nb\nc\nd\ne\nchanged\n"),
            ("a", "a\n"),
            ("", "new\n"),
            ("old\n", ""),
        ] {
            let diff = bounded_diff(current, candidate);
            let patch = diffy::Patch::from_str(&diff).unwrap();
            assert_eq!(diffy::apply(current, &patch).unwrap(), candidate);
        }
    }
}
