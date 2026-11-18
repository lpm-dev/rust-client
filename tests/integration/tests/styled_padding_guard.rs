//! Padding text that is already colored lines nothing up: `{:<8}` counts the
//! characters of a `String`, and `lpm_common::color::Painted` returns one
//! with its escape sequences inside, so the column comes out short by their
//! length. Pad first and color the padded text, or pass an
//! `install_ui::TerminalFragment`, which pads by the columns it takes on
//! screen.

use std::path::{Path, PathBuf};

use syn::punctuated::Punctuated;
use syn::visit::Visit;
use syn::{
    Attribute, Expr, ExprLit, ExprMethodCall, ImplItemFn, ItemFn, ItemMod, Lit, Macro, Token,
};

const FORMAT_MACROS: &[&str] = &[
    "format",
    "format_args",
    "print",
    "println",
    "eprint",
    "eprintln",
    "write",
    "writeln",
    "panic",
    "terminal_line",
];

const PAINTED_METHODS: &[&str] = &[
    "green",
    "red",
    "yellow",
    "cyan",
    "blue",
    "magenta",
    "white",
    "bold",
    "dimmed",
    "italic",
    "underline",
    "bright_red",
    "bright_green",
    "bright_yellow",
    "bright_cyan",
    "bright_blue",
    "bright_magenta",
    "bright_white",
    "bright_black",
    "on_red",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical workspace root")
}

fn rust_sources(dir: &Path, sources: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|error| panic!("read {dir:?}: {error}"));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test"))
    })
}

/// A placeholder's argument and whether it asks for a minimum width.
struct Placeholder {
    argument: Argument,
    has_width: bool,
}

enum Argument {
    Next,
    Index(usize),
    Named(String),
}

/// Reads the placeholders of a format string, skipping `{{` and `}}`.
fn placeholders(format: &str) -> Vec<Placeholder> {
    let mut found = Vec::new();
    let mut chars = format.char_indices().peekable();
    while let Some((start, character)) = chars.next() {
        if character == '}' {
            chars.next_if(|(_, next)| *next == '}');
            continue;
        }
        if character != '{' {
            continue;
        }
        if chars.next_if(|(_, next)| *next == '{').is_some() {
            continue;
        }
        let Some(end) = format[start..].find('}').map(|offset| start + offset) else {
            break;
        };
        let inner = &format[start + 1..end];
        while chars.next_if(|(index, _)| *index <= end).is_some() {}

        let (name, spec) = inner.split_once(':').unwrap_or((inner, ""));
        let name = name.trim();
        let argument = if name.is_empty() {
            Argument::Next
        } else if let Ok(index) = name.parse() {
            Argument::Index(index)
        } else {
            Argument::Named(name.to_owned())
        };
        found.push(Placeholder {
            argument,
            has_width: spec_has_width(spec),
        });
    }
    found
}

/// `[[fill]align][sign]['#']['0'][width]['.' precision][type]`: whether a
/// width follows the fill, alignment and flags.
fn spec_has_width(spec: &str) -> bool {
    let mut rest = spec;
    let mut characters = rest.chars();
    if let (Some(first), Some(second)) = (characters.next(), characters.next()) {
        if matches!(second, '<' | '^' | '>') {
            rest = &rest[first.len_utf8() + 1..];
        } else if matches!(first, '<' | '^' | '>') {
            rest = &rest[1..];
        }
    } else if matches!(rest, "<" | "^" | ">") {
        rest = "";
    }
    let rest = rest.trim_start_matches(['+', '-']);
    let rest = rest.strip_prefix('#').unwrap_or(rest);
    let rest = rest.strip_prefix('0').unwrap_or(rest);
    let width = rest.split('.').next().unwrap_or("");
    let width = width.trim_end_matches(|character: char| {
        !character.is_alphanumeric() && character != '_' && character != '$'
    });
    width.starts_with(|character: char| character.is_ascii_digit())
        || (width.ends_with('$') && width.len() > 1)
}

#[derive(Default)]
struct PaintedCallFinder {
    method: Option<String>,
}

impl<'ast> Visit<'ast> for PaintedCallFinder {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();
        if self.method.is_none()
            && call.args.is_empty()
            && PAINTED_METHODS.contains(&method.as_str())
        {
            self.method = Some(method);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// The first `Painted` method the expression calls, such as `dimmed`.
fn painted_call(expr: &Expr) -> Option<String> {
    let mut finder = PaintedCallFinder::default();
    finder.visit_expr(expr);
    finder.method
}

struct StyledPaddingAudit {
    relative: String,
    current_function: Option<String>,
    violations: Vec<String>,
}

impl StyledPaddingAudit {
    fn audit_format_macro(&mut self, mac: &Macro) {
        let Ok(arguments) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        else {
            return;
        };
        let Some(format_index) = arguments.iter().position(|argument| {
            matches!(
                argument,
                Expr::Lit(ExprLit {
                    lit: Lit::Str(_),
                    ..
                })
            )
        }) else {
            return;
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(format),
            ..
        }) = &arguments[format_index]
        else {
            return;
        };
        let rest: Vec<&Expr> = arguments.iter().skip(format_index + 1).collect();
        let positional: Vec<&Expr> = rest
            .iter()
            .copied()
            .filter(|argument| !matches!(argument, Expr::Assign(_)))
            .collect();
        let named = |name: &str| {
            rest.iter().find_map(|argument| match argument {
                Expr::Assign(assign) => match assign.left.as_ref() {
                    Expr::Path(path) if path.path.is_ident(name) => Some(assign.right.as_ref()),
                    _ => None,
                },
                _ => None,
            })
        };

        let mut next = 0;
        for placeholder in placeholders(&format.value()) {
            let argument = match &placeholder.argument {
                Argument::Next => {
                    next += 1;
                    positional.get(next - 1).copied()
                }
                Argument::Index(index) => positional.get(*index).copied(),
                Argument::Named(name) => named(name),
            };
            if placeholder.has_width
                && let Some(method) = argument.and_then(painted_call)
            {
                self.violations.push(format!(
                    "{}: {}: {:?} pads the result of `.{method}()`",
                    self.relative,
                    self.current_function.as_deref().unwrap_or("<module>"),
                    format.value(),
                ));
            }
        }
        for argument in arguments.iter() {
            self.visit_expr(argument);
        }
    }
}

impl<'ast> Visit<'ast> for StyledPaddingAudit {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if !is_test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_test_only(&item.attrs) {
            let previous = self.current_function.replace(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.current_function = previous;
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        if !is_test_only(&item.attrs) {
            let previous = self.current_function.replace(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.current_function = previous;
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let is_format_macro = mac
            .path
            .segments
            .last()
            .is_some_and(|segment| FORMAT_MACROS.contains(&segment.ident.to_string().as_str()));
        if is_format_macro {
            self.audit_format_macro(mac);
        }
        syn::visit::visit_macro(self, mac);
    }
}

#[test]
fn format_widths_never_pad_text_that_is_already_colored() {
    let root = workspace_root();
    let mut sources = Vec::new();
    let crates = root.join("crates");
    for entry in std::fs::read_dir(&crates).expect("read crates") {
        let src = entry.expect("crate entry").path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut sources);
        }
    }
    sources.sort();
    assert!(
        sources.len() > 100,
        "the guard must scan the workspace's sources, found {}",
        sources.len()
    );

    let mut violations = Vec::new();
    for path in sources {
        let relative = path
            .strip_prefix(&root)
            .expect("source under the workspace")
            .display()
            .to_string();
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {relative}: {error}"));
        let syntax =
            syn::parse_file(&source).unwrap_or_else(|error| panic!("parse {relative}: {error}"));
        let mut audit = StyledPaddingAudit {
            relative,
            current_function: None,
            violations: Vec::new(),
        };
        audit.visit_file(&syntax);
        violations.extend(audit.violations);
    }

    assert!(
        violations.is_empty(),
        "pad before coloring, or pad an install_ui::TerminalFragment:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_guard_flags_a_width_on_painted_text() {
    let syntax: syn::File = syn::parse_quote! {
        fn render(section: &str, name: &str, wanted: usize) {
            println!("{:<wanted$}  {}", section.dimmed(), name);
            println!("{0:>8} {label:<4}", name, label = section.cyan());
            let ok = format!("{:<8}", name).dimmed();
            let fine = format!("{}", section.dimmed());
        }
    };
    let mut audit = StyledPaddingAudit {
        relative: "example.rs".to_owned(),
        current_function: None,
        violations: Vec::new(),
    };
    audit.visit_file(&syntax);

    assert_eq!(
        audit.violations,
        [
            "example.rs: render: \"{:<wanted$}  {}\" pads the result of `.dimmed()`",
            "example.rs: render: \"{0:>8} {label:<4}\" pads the result of `.cyan()`",
        ]
    );
}

#[test]
fn format_specs_with_a_width_are_recognized() {
    for spec in ["<8", "8", ">w$", "-^10", "x<12.3", "08", "#010x", "<width$"] {
        assert!(spec_has_width(spec), "{spec:?} has a width");
    }
    for spec in ["", "?", "#?", ".3", "<", "x"] {
        assert!(!spec_has_width(spec), "{spec:?} has no width");
    }
}
