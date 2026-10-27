//! Characters in env values that are hard to see, or that change how the text
//! around them reads: zero-width and other default-ignorable characters,
//! direction controls, spaces other than the plain space, controls, line
//! breaks other than `\n`, and whitespace at either end of a value.
//!
//! One pass over a value finds them and where they are, so the CLI and LPM
//! Vault can say which key holds them, which characters they are and where,
//! without showing the value. Nothing here changes a value unless the caller
//! asks for one of the fixes, [`remove_hidden_characters`] and [`trim_ends`].
//!
//! Text that needs these characters isn't flagged: line breaks inside a
//! multiline value and the single final newline such a value often ends with,
//! emoji sequences, joiners in scripts that shape with them, and a variation
//! selector right after a character it varies.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::ops::Range;

use icu_properties::props::{
    CanonicalCombiningClass, Emoji, EmojiModifier, ExtendedPictographic, JoiningType,
    UnifiedIdeograph,
};
use icu_properties::{
    CodePointMapData, CodePointMapDataBorrowed, CodePointSetData, CodePointSetDataBorrowed,
};

/// The most characters one value's report lists; `more` counts the others.
pub const MAX_LISTED_CHARACTERS: usize = 8;
/// The most runs one listed character gives; its `count` still counts every one.
pub const MAX_LISTED_RUNS: usize = 8;

/// Why a character is flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharacterKind {
    /// Whitespace before the value's first other character.
    LeadingWhitespace,
    /// Whitespace after the value's last other character.
    TrailingWhitespace,
    /// A format or other default-ignorable character, which draws nothing.
    Invisible,
    /// A character that changes the direction text runs in.
    Direction,
    /// A space other than U+0020, a tab, or the blank Braille cell.
    Space,
    /// A line break other than `\n`.
    LineBreak,
    /// Any other control character.
    Control,
}

impl CharacterKind {
    /// The stable code the CLI's JSON and the engine's output use.
    pub const fn code(self) -> &'static str {
        match self {
            Self::LeadingWhitespace => "leading_whitespace",
            Self::TrailingWhitespace => "trailing_whitespace",
            Self::Invisible => "invisible",
            Self::Direction => "direction",
            Self::Space => "space",
            Self::LineBreak => "line_break",
            Self::Control => "control",
        }
    }

    /// Whether [`trim_ends`] removes it, rather than [`remove_hidden_characters`].
    pub const fn is_at_an_end(self) -> bool {
        matches!(self, Self::LeadingWhitespace | Self::TrailingWhitespace)
    }
}

/// Which character was found. Characters that can spell out text that
/// doesn't show are reported as a group, never one by one, since telling
/// them apart would show the text they hide, which is part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiddenCharacter {
    Char(char),
    /// Unicode tag characters, U+E0000–U+E007F.
    Tags,
    /// Variation selectors, U+FE00–U+FE0F and U+E0100–U+E01EF.
    VariationSelectors,
    /// Default-ignorable code points Unicode hasn't assigned yet.
    Unassigned,
}

impl HiddenCharacter {
    /// Such as `U+200B`; none for a group.
    pub fn code_point(self) -> Option<String> {
        match self {
            Self::Char(character) => Some(format!("U+{:04X}", u32::from(character))),
            _ => None,
        }
    }

    /// The character as an escape, such as `\u{200b}` or `\t`; none for a group.
    pub fn escape(self) -> Option<String> {
        match self {
            Self::Char(character) => {
                let mut escape = String::with_capacity(10);
                push_escape(&mut escape, character);
                Some(escape)
            }
            _ => None,
        }
    }

    /// The character's Unicode name, or for a control its Unicode name
    /// alias, such as `ZERO WIDTH SPACE` or `CHARACTER TABULATION`; for a
    /// group, what it holds, such as `tag characters`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Char(character) => unicode_name(character),
            Self::Tags => "tag characters",
            Self::VariationSelectors => "variation selectors",
            Self::Unassigned => "unassigned invisible characters",
        }
    }

    /// The group's stable code; none for a single character.
    pub const fn group(self) -> Option<&'static str> {
        match self {
            Self::Char(_) => None,
            Self::Tags => Some("tags"),
            Self::VariationSelectors => Some("variation_selectors"),
            Self::Unassigned => Some("unassigned"),
        }
    }
}

/// Consecutive occurrences, counted in characters (Unicode scalar values)
/// from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharacterRun {
    pub position: usize,
    pub count: usize,
}

/// One character found in a value, or one group, of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundCharacter {
    pub kind: CharacterKind,
    pub character: HiddenCharacter,
    /// Every occurrence, listed in `runs` or not.
    pub count: usize,
    /// The first [`MAX_LISTED_RUNS`] runs, in order.
    pub runs: Vec<CharacterRun>,
}

impl FoundCharacter {
    /// Such as `\u{200b} ZERO WIDTH SPACE at character 4`,
    /// `\u{20} SPACE ×2 at the end` or `tag characters ×28 at characters 12–39`.
    /// Never quotes the value.
    pub fn describe(&self) -> String {
        let name = self.character.name();
        let mut text = match self.character.escape() {
            Some(escape) => format!("{escape} {name}"),
            None => name.to_owned(),
        };
        if self.count > 1 {
            let _ = write!(text, " ×{}", self.count);
        }
        match self.kind {
            CharacterKind::LeadingWhitespace => text.push_str(" at the start"),
            CharacterKind::TrailingWhitespace => text.push_str(" at the end"),
            _ => {
                let listed: usize = self.runs.iter().map(|run| run.count).sum();
                text.push_str(if listed == 1 && self.count == 1 {
                    " at character "
                } else {
                    " at characters "
                });
                for (index, run) in self.runs.iter().enumerate() {
                    if index > 0 {
                        text.push_str(", ");
                    }
                    let _ = write!(text, "{}", run.position);
                    if run.count > 1 {
                        let _ = write!(text, "–{}", run.position + run.count - 1);
                    }
                }
                if listed < self.count {
                    text.push_str(", …");
                }
            }
        }
        text
    }
}

/// What one value holds that's hard to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCharacters {
    /// The first [`MAX_LISTED_CHARACTERS`] characters found, by where each
    /// first appears.
    pub characters: Vec<FoundCharacter>,
    /// How many more characters, or groups, were found and not listed.
    pub more: usize,
    /// Whether [`remove_hidden_characters`] changes the value.
    pub removable: bool,
    /// Whether [`trim_ends`] changes the value.
    pub trimmable: bool,
}

/// What `value` holds that's hard to see, in one pass; none when nothing is.
pub fn check_value_characters(value: &str) -> Option<ValueCharacters> {
    let mut found = Found::default();
    scan(value, |flagged| found.add(flagged));
    found.finish()
}

/// `value` with each flagged character other than whitespace at an end
/// removed, or, for a space other than U+0020 or a tab, made a plain space,
/// and for a line break other than `\n`, made one, except the carriage return
/// of a `\r\n`, which is removed, so a file's line endings become `\n`.
pub fn remove_hidden_characters(value: &str) -> Cow<'_, str> {
    let mut fixed: Option<String> = None;
    let mut copied = 0;
    scan(value, |flagged| {
        let replacement = match flagged.replacement {
            Replacement::Trimmed => return,
            Replacement::Removed => "",
            Replacement::Space => " ",
            Replacement::LineFeed => "\n",
        };
        let fixed = fixed.get_or_insert_with(|| String::with_capacity(value.len()));
        fixed.push_str(&value[copied..flagged.bytes.start]);
        fixed.push_str(replacement);
        copied = flagged.bytes.end;
    });
    match fixed {
        None => Cow::Borrowed(value),
        Some(mut fixed) => {
            fixed.push_str(&value[copied..]);
            Cow::Owned(fixed)
        }
    }
}

/// `value` without the whitespace at either end that
/// [`check_value_characters`] flags, so the single final line break of a
/// multiline value stays.
pub fn trim_ends(value: &str) -> &str {
    let edges = Edges::of(value);
    let end = if edges.ends_with_a_line_break(value) {
        value.len()
    } else {
        edges.trailing
    };
    &value[edges.leading..end]
}

/// A value shown with each flagged character written as its escape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownCharacters {
    pub text: String,
    /// Where each escape is in `text`, in UTF-16 code units.
    pub marks: Vec<Range<usize>>,
}

/// `value` with each character [`check_value_characters`] flags written as
/// its escape, such as `\u{200b}`, for showing someone who sees the value.
pub fn show_hidden_characters(value: &str) -> ShownCharacters {
    let mut text = String::with_capacity(value.len());
    let mut marks = Vec::new();
    let mut copied = 0;
    let mut utf16 = 0;
    scan(value, |flagged| {
        let unflagged = &value[copied..flagged.bytes.start];
        text.push_str(unflagged);
        utf16 += unflagged.chars().map(char::len_utf16).sum::<usize>();
        let start = text.len();
        push_escape(&mut text, flagged.character);
        // An escape is ASCII, so its UTF-16 length is its byte length.
        let length = text.len() - start;
        marks.push(utf16..utf16 + length);
        utf16 += length;
        copied = flagged.bytes.end;
    });
    text.push_str(&value[copied..]);
    ShownCharacters { text, marks }
}

/// What [`remove_hidden_characters`] puts in a flagged character's place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Replacement {
    /// Whitespace at an end, which only [`trim_ends`] removes.
    Trimmed,
    Removed,
    Space,
    LineFeed,
}

struct Flagged {
    /// Counted in characters from 1.
    position: usize,
    bytes: Range<usize>,
    character: char,
    kind: CharacterKind,
    identity: HiddenCharacter,
    replacement: Replacement,
}

/// Where the whitespace at either end of a value is, by byte offset.
struct Edges {
    /// Where the leading whitespace ends.
    leading: usize,
    /// Where the trailing whitespace starts; never before `leading`, so a
    /// value of only whitespace has it all leading.
    trailing: usize,
}

impl Edges {
    fn of(value: &str) -> Self {
        let leading = value.len() - value.trim_start().len();
        let trailing = value.trim_end().len().max(leading);
        Self { leading, trailing }
    }

    /// Whether the trailing whitespace is one line break, `\n` or `\r\n`,
    /// ending a value that already spans lines, as a PEM file does: part of
    /// the text, not a stray end.
    fn ends_with_a_line_break(&self, value: &str) -> bool {
        is_one_line_break(&value[self.trailing..])
            && value[self.leading..self.trailing].contains('\n')
    }
}

/// The characters before the one being classified that decide whether it
/// belongs where it is.
#[derive(Default)]
struct Context {
    previous: Option<char>,
    /// The nearest previous character that isn't transparent to joining.
    previous_joining: Option<char>,
    /// The previous character ends an emoji, so a zero width joiner may
    /// follow it within an emoji sequence.
    ends_emoji: bool,
}

/// Visits each flagged character of `value` in order, in one pass.
fn scan(value: &str, mut visit: impl FnMut(&Flagged)) {
    let edges = Edges::of(value);
    let trailing_is_one_line_break = is_one_line_break(&value[edges.trailing..]);
    let mut inner_newline = false;
    let mut context = Context::default();
    // Tag characters before this byte belong to an emoji flag sequence.
    let mut flag_ends = 0;
    let mut chars = value.char_indices().peekable();
    let mut position = 0;
    while let Some((at, character)) = chars.next() {
        position += 1;
        let bytes = at..at + character.len_utf8();
        if at < edges.leading || at >= edges.trailing {
            let (kind, replacement) = if at < edges.leading {
                (CharacterKind::LeadingWhitespace, Replacement::Trimmed)
            } else if trailing_is_one_line_break && inner_newline {
                // A multiline value's final line break is text; only the
                // carriage return of a final `\r\n` is stray.
                if character == '\n' {
                    continue;
                }
                (CharacterKind::LineBreak, Replacement::Removed)
            } else {
                (CharacterKind::TrailingWhitespace, Replacement::Trimmed)
            };
            visit(&Flagged {
                position,
                bytes,
                character,
                kind,
                identity: HiddenCharacter::Char(character),
                replacement,
            });
            context = Context {
                previous: Some(character),
                previous_joining: Some(character),
                ends_emoji: false,
            };
            continue;
        }
        if matches!(character, ' '..='~') {
            context = Context {
                previous: Some(character),
                previous_joining: Some(character),
                ends_emoji: false,
            };
            continue;
        }
        if character == '\n' {
            inner_newline = true;
        }
        if character == '\u{1F3F4}' {
            flag_ends = flag_tags_end(value, bytes.end);
        }
        let next = chars.peek().map(|&(_, next)| next);
        let found = if at < flag_ends {
            None
        } else {
            classify(character, &context, next)
        };
        if let Some((kind, identity, replacement)) = found {
            visit(&Flagged {
                position,
                bytes,
                character,
                kind,
                identity,
                replacement,
            });
        }
        let joins_emoji = match character {
            '\u{FE0E}' | '\u{FE0F}' | '\u{E007F}' => found.is_none() && context.ends_emoji_base(),
            _ => is_emoji_element_end(character),
        };
        context.ends_emoji = joins_emoji;
        context.previous = Some(character);
        if JOINING_TYPES.get(character) != JoiningType::Transparent {
            context.previous_joining = Some(character);
        }
    }
}

impl Context {
    /// Whether a variation selector or a flag's cancel tag that follows ends
    /// an emoji: the character it follows is one.
    fn ends_emoji_base(&self) -> bool {
        self.previous.is_some_and(|previous| {
            EMOJI.contains(previous) || (0xE0020..=0xE007E).contains(&u32::from(previous))
        })
    }
}

fn is_one_line_break(text: &str) -> bool {
    matches!(text, "\n" | "\r\n")
}

fn is_emoji_element_end(character: char) -> bool {
    EXTENDED_PICTOGRAPHIC.contains(character) || EMOJI_MODIFIERS.contains(character)
}

/// The end of the tag characters after a waving black flag at `after`, when
/// they spell one of the subdivision flags Unicode recommends: England,
/// Scotland or Wales. Their letters are fixed, so they hide nothing. Any other
/// tag sequence could spell out anything, so it stays flagged.
fn flag_tags_end(value: &str, after: usize) -> usize {
    const FLAGS: [&str; 3] = [
        "\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
        "\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
        "\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}",
    ];
    let rest = &value[after..];
    FLAGS
        .iter()
        .find(|flag| rest.starts_with(*flag))
        .map_or(0, |flag| after + flag.len())
}

/// Why `character`, inside a value, is flagged, with its identity and fix;
/// none when it isn't.
fn classify(
    character: char,
    context: &Context,
    next: Option<char>,
) -> Option<(CharacterKind, HiddenCharacter, Replacement)> {
    use CharacterKind::{Control, Direction, Invisible, LineBreak, Space};
    let single = HiddenCharacter::Char(character);
    let found = match character {
        '\n' => return None,
        '\t' => (Space, single, Replacement::Space),
        '\r' if next == Some('\n') => (LineBreak, single, Replacement::Removed),
        '\r' | '\u{B}' | '\u{C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
            (LineBreak, single, Replacement::LineFeed)
        }
        _ if character.is_control() => (Control, single, Replacement::Removed),
        '\u{A0}'
        | '\u{1680}'
        | '\u{2000}'..='\u{200A}'
        | '\u{202F}'
        | '\u{205F}'
        | '\u{3000}'
        | '\u{2800}' => (Space, single, Replacement::Space),
        '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
            (Direction, single, Replacement::Removed)
        }
        '\u{E0000}'..='\u{E007F}' => (Invisible, HiddenCharacter::Tags, Replacement::Removed),
        '\u{FE0E}' | '\u{FE0F}' if context.previous.is_some_and(|base| EMOJI.contains(base)) => {
            return None;
        }
        // Ideographic variation sequences, and the standardized variants
        // that stand for CJK compatibility ideographs, such as U+4FAE U+FE00.
        '\u{E0100}'..='\u{E01EF}' | '\u{FE00}'..='\u{FE02}'
            if context
                .previous
                .is_some_and(|base| UNIFIED_IDEOGRAPHS.contains(base)) =>
        {
            return None;
        }
        '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}' => (
            Invisible,
            HiddenCharacter::VariationSelectors,
            Replacement::Removed,
        ),
        '\u{200C}' | '\u{200D}' if joins_in_context(character, context, next) => return None,
        '\u{180B}'..='\u{180D}' | '\u{180F}'
            if context.previous.is_some_and(is_mongolian_letter) =>
        {
            return None;
        }
        '\u{180E}'
            if context.previous.is_some_and(is_mongolian_letter)
                && next.is_some_and(is_mongolian_letter) =>
        {
            return None;
        }
        '\u{2065}'
        | '\u{FFF0}'..='\u{FFF8}'
        | '\u{E0080}'..='\u{E00FF}'
        | '\u{E01F0}'..='\u{E0FFF}' => {
            (Invisible, HiddenCharacter::Unassigned, Replacement::Removed)
        }
        '\u{AD}'
        | '\u{34F}'
        | '\u{115F}'
        | '\u{1160}'
        | '\u{17B4}'
        | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200D}'
        | '\u{2060}'..='\u{2064}'
        | '\u{206A}'..='\u{206F}'
        | '\u{3164}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' => (Invisible, single, Replacement::Removed),
        _ => return None,
    };
    Some(found)
}

/// Whether a zero width joiner or non-joiner is part of the text around it:
/// a joiner between the parts of an emoji, either next to a virama, as Indic
/// scripts write half forms and conjuncts, or between letters of a script
/// that joins its letters, as Persian writes a non-joiner inside words.
fn joins_in_context(character: char, context: &Context, next: Option<char>) -> bool {
    let Some(next) = next else {
        return context.previous.is_some_and(is_virama);
    };
    if character == '\u{200D}'
        && context.ends_emoji
        && (EXTENDED_PICTOGRAPHIC.contains(next) || (EMOJI.contains(next) && !next.is_ascii()))
    {
        return true;
    }
    if context.previous.is_some_and(is_virama) || is_virama(next) {
        return true;
    }
    let joins = |neighbor: char| {
        !matches!(neighbor, '\u{200C}' | '\u{200D}')
            && matches!(
                JOINING_TYPES.get(neighbor),
                JoiningType::DualJoining
                    | JoiningType::LeftJoining
                    | JoiningType::RightJoining
                    | JoiningType::JoinCausing
            )
    };
    context.previous_joining.is_some_and(joins) && joins(next)
}

fn is_virama(character: char) -> bool {
    COMBINING_CLASSES.get(character) == CanonicalCombiningClass::Virama
}

/// The letters of the Mongolian block, which free variation selectors and
/// the vowel separator shape.
fn is_mongolian_letter(character: char) -> bool {
    matches!(character, '\u{1820}'..='\u{1878}' | '\u{1880}'..='\u{1884}' | '\u{1887}'..='\u{18A8}' | '\u{18AA}')
}

const EMOJI: CodePointSetDataBorrowed<'static> = CodePointSetData::new::<Emoji>();
const EMOJI_MODIFIERS: CodePointSetDataBorrowed<'static> = CodePointSetData::new::<EmojiModifier>();
const EXTENDED_PICTOGRAPHIC: CodePointSetDataBorrowed<'static> =
    CodePointSetData::new::<ExtendedPictographic>();
const UNIFIED_IDEOGRAPHS: CodePointSetDataBorrowed<'static> =
    CodePointSetData::new::<UnifiedIdeograph>();
const JOINING_TYPES: CodePointMapDataBorrowed<'static, JoiningType> =
    CodePointMapData::<JoiningType>::new();
const COMBINING_CLASSES: CodePointMapDataBorrowed<'static, CanonicalCombiningClass> =
    CodePointMapData::<CanonicalCombiningClass>::new();

/// Collects a value's flagged characters into its report, within its limits.
#[derive(Default)]
struct Found {
    characters: Vec<FoundCharacter>,
    unlisted: HashSet<(CharacterKind, HiddenCharacter)>,
    removable: bool,
    trimmable: bool,
}

impl Found {
    fn add(&mut self, flagged: &Flagged) {
        if flagged.kind.is_at_an_end() {
            self.trimmable = true;
        } else {
            self.removable = true;
        }
        let index = self
            .characters
            .iter()
            .position(|found| found.kind == flagged.kind && found.character == flagged.identity);
        let index = match index {
            Some(index) => index,
            None if self.characters.len() < MAX_LISTED_CHARACTERS => {
                self.characters.push(FoundCharacter {
                    kind: flagged.kind,
                    character: flagged.identity,
                    count: 0,
                    runs: Vec::new(),
                });
                self.characters.len() - 1
            }
            None => {
                self.unlisted.insert((flagged.kind, flagged.identity));
                return;
            }
        };
        let found = &mut self.characters[index];
        found.count += 1;
        let listed = found.runs.len();
        match found.runs.last_mut() {
            Some(run) if run.position + run.count == flagged.position => run.count += 1,
            _ if listed < MAX_LISTED_RUNS => found.runs.push(CharacterRun {
                position: flagged.position,
                count: 1,
            }),
            _ => {}
        }
    }

    fn finish(self) -> Option<ValueCharacters> {
        if self.characters.is_empty() {
            return None;
        }
        Some(ValueCharacters {
            characters: self.characters,
            more: self.unlisted.len(),
            removable: self.removable,
            trimmable: self.trimmable,
        })
    }
}

fn push_escape(text: &mut String, character: char) {
    match character {
        '\t' => text.push_str("\\t"),
        '\n' => text.push_str("\\n"),
        '\r' => text.push_str("\\r"),
        _ => {
            let _ = write!(text, "\\u{{{:x}}}", u32::from(character));
        }
    }
}

const C0_CONTROL_NAMES: [&str; 32] = [
    "NULL",
    "START OF HEADING",
    "START OF TEXT",
    "END OF TEXT",
    "END OF TRANSMISSION",
    "ENQUIRY",
    "ACKNOWLEDGE",
    "ALERT",
    "BACKSPACE",
    "CHARACTER TABULATION",
    "LINE FEED",
    "LINE TABULATION",
    "FORM FEED",
    "CARRIAGE RETURN",
    "SHIFT OUT",
    "SHIFT IN",
    "DATA LINK ESCAPE",
    "DEVICE CONTROL ONE",
    "DEVICE CONTROL TWO",
    "DEVICE CONTROL THREE",
    "DEVICE CONTROL FOUR",
    "NEGATIVE ACKNOWLEDGE",
    "SYNCHRONOUS IDLE",
    "END OF TRANSMISSION BLOCK",
    "CANCEL",
    "END OF MEDIUM",
    "SUBSTITUTE",
    "ESCAPE",
    "INFORMATION SEPARATOR FOUR",
    "INFORMATION SEPARATOR THREE",
    "INFORMATION SEPARATOR TWO",
    "INFORMATION SEPARATOR ONE",
];

const C1_CONTROL_NAMES: [&str; 32] = [
    "PADDING CHARACTER",
    "HIGH OCTET PRESET",
    "BREAK PERMITTED HERE",
    "NO BREAK HERE",
    "INDEX",
    "NEXT LINE",
    "START OF SELECTED AREA",
    "END OF SELECTED AREA",
    "CHARACTER TABULATION SET",
    "CHARACTER TABULATION WITH JUSTIFICATION",
    "LINE TABULATION SET",
    "PARTIAL LINE FORWARD",
    "PARTIAL LINE BACKWARD",
    "REVERSE LINE FEED",
    "SINGLE SHIFT TWO",
    "SINGLE SHIFT THREE",
    "DEVICE CONTROL STRING",
    "PRIVATE USE ONE",
    "PRIVATE USE TWO",
    "SET TRANSMIT STATE",
    "CANCEL CHARACTER",
    "MESSAGE WAITING",
    "START OF GUARDED AREA",
    "END OF GUARDED AREA",
    "START OF STRING",
    "SINGLE GRAPHIC CHARACTER INTRODUCER",
    "SINGLE CHARACTER INTRODUCER",
    "CONTROL SEQUENCE INTRODUCER",
    "STRING TERMINATOR",
    "OPERATING SYSTEM COMMAND",
    "PRIVACY MESSAGE",
    "APPLICATION PROGRAM COMMAND",
];

/// The Unicode name of each character this module reports by itself, or a
/// control's name alias, since controls have no name. Empty for any other.
fn unicode_name(character: char) -> &'static str {
    let code = u32::from(character) as usize;
    match character {
        '\u{0}'..='\u{1F}' => C0_CONTROL_NAMES[code],
        '\u{7F}' => "DELETE",
        '\u{80}'..='\u{9F}' => C1_CONTROL_NAMES[code - 0x80],
        ' ' => "SPACE",
        '\u{A0}' => "NO-BREAK SPACE",
        '\u{AD}' => "SOFT HYPHEN",
        '\u{34F}' => "COMBINING GRAPHEME JOINER",
        '\u{61C}' => "ARABIC LETTER MARK",
        '\u{115F}' => "HANGUL CHOSEONG FILLER",
        '\u{1160}' => "HANGUL JUNGSEONG FILLER",
        '\u{1680}' => "OGHAM SPACE MARK",
        '\u{17B4}' => "KHMER VOWEL INHERENT AQ",
        '\u{17B5}' => "KHMER VOWEL INHERENT AA",
        '\u{180B}' => "MONGOLIAN FREE VARIATION SELECTOR ONE",
        '\u{180C}' => "MONGOLIAN FREE VARIATION SELECTOR TWO",
        '\u{180D}' => "MONGOLIAN FREE VARIATION SELECTOR THREE",
        '\u{180E}' => "MONGOLIAN VOWEL SEPARATOR",
        '\u{180F}' => "MONGOLIAN FREE VARIATION SELECTOR FOUR",
        '\u{2000}' => "EN QUAD",
        '\u{2001}' => "EM QUAD",
        '\u{2002}' => "EN SPACE",
        '\u{2003}' => "EM SPACE",
        '\u{2004}' => "THREE-PER-EM SPACE",
        '\u{2005}' => "FOUR-PER-EM SPACE",
        '\u{2006}' => "SIX-PER-EM SPACE",
        '\u{2007}' => "FIGURE SPACE",
        '\u{2008}' => "PUNCTUATION SPACE",
        '\u{2009}' => "THIN SPACE",
        '\u{200A}' => "HAIR SPACE",
        '\u{200B}' => "ZERO WIDTH SPACE",
        '\u{200C}' => "ZERO WIDTH NON-JOINER",
        '\u{200D}' => "ZERO WIDTH JOINER",
        '\u{200E}' => "LEFT-TO-RIGHT MARK",
        '\u{200F}' => "RIGHT-TO-LEFT MARK",
        '\u{2028}' => "LINE SEPARATOR",
        '\u{2029}' => "PARAGRAPH SEPARATOR",
        '\u{202A}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202B}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202C}' => "POP DIRECTIONAL FORMATTING",
        '\u{202D}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202E}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{202F}' => "NARROW NO-BREAK SPACE",
        '\u{205F}' => "MEDIUM MATHEMATICAL SPACE",
        '\u{2060}' => "WORD JOINER",
        '\u{2061}' => "FUNCTION APPLICATION",
        '\u{2062}' => "INVISIBLE TIMES",
        '\u{2063}' => "INVISIBLE SEPARATOR",
        '\u{2064}' => "INVISIBLE PLUS",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",
        '\u{206A}' => "INHIBIT SYMMETRIC SWAPPING",
        '\u{206B}' => "ACTIVATE SYMMETRIC SWAPPING",
        '\u{206C}' => "INHIBIT ARABIC FORM SHAPING",
        '\u{206D}' => "ACTIVATE ARABIC FORM SHAPING",
        '\u{206E}' => "NATIONAL DIGIT SHAPES",
        '\u{206F}' => "NOMINAL DIGIT SHAPES",
        '\u{2800}' => "BRAILLE PATTERN BLANK",
        '\u{3000}' => "IDEOGRAPHIC SPACE",
        '\u{3164}' => "HANGUL FILLER",
        '\u{FEFF}' => "ZERO WIDTH NO-BREAK SPACE",
        '\u{FFA0}' => "HALFWIDTH HANGUL FILLER",
        '\u{FFF9}' => "INTERLINEAR ANNOTATION ANCHOR",
        '\u{FFFA}' => "INTERLINEAR ANNOTATION SEPARATOR",
        '\u{FFFB}' => "INTERLINEAR ANNOTATION TERMINATOR",
        '\u{1BCA0}' => "SHORTHAND FORMAT LETTER OVERLAP",
        '\u{1BCA1}' => "SHORTHAND FORMAT CONTINUING OVERLAP",
        '\u{1BCA2}' => "SHORTHAND FORMAT DOWN STEP",
        '\u{1BCA3}' => "SHORTHAND FORMAT UP STEP",
        '\u{1D173}' => "MUSICAL SYMBOL BEGIN BEAM",
        '\u{1D174}' => "MUSICAL SYMBOL END BEAM",
        '\u{1D175}' => "MUSICAL SYMBOL BEGIN TIE",
        '\u{1D176}' => "MUSICAL SYMBOL END TIE",
        '\u{1D177}' => "MUSICAL SYMBOL BEGIN SLUR",
        '\u{1D178}' => "MUSICAL SYMBOL END SLUR",
        '\u{1D179}' => "MUSICAL SYMBOL BEGIN PHRASE",
        '\u{1D17A}' => "MUSICAL SYMBOL END PHRASE",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icu_properties::props::{DefaultIgnorableCodePoint, GeneralCategory};

    /// A finding as (kind, character, count, runs as (position, count)).
    type Finding = (CharacterKind, HiddenCharacter, usize, Vec<(usize, usize)>);

    fn findings(value: &str) -> Vec<Finding> {
        check_value_characters(value)
            .map(|found| {
                found
                    .characters
                    .into_iter()
                    .map(|found| {
                        let runs = found
                            .runs
                            .iter()
                            .map(|run| (run.position, run.count))
                            .collect();
                        (found.kind, found.character, found.count, runs)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn single(value: &str) -> (CharacterKind, HiddenCharacter, Vec<(usize, usize)>) {
        let mut found = findings(value);
        assert_eq!(
            found.len(),
            1,
            "expected one finding in {value:?}, got {found:?}"
        );
        let (kind, character, _, runs) = found.remove(0);
        (kind, character, runs)
    }

    fn assert_clean(value: &str) {
        let preview: String = value.chars().take(40).collect();
        assert_eq!(
            check_value_characters(value),
            None,
            "{preview:?} must not be flagged"
        );
    }

    #[test]
    fn ordinary_values_are_not_flagged() {
        for value in [
            "",
            "sk_live_51HxAbC0123456789",
            "postgres://user:p%40ss@db.example.com:5432/app?sslmode=require",
            "two words with inner spaces",
            "{\"a\": 1, \"b\": [true, null]}",
        ] {
            assert_clean(value);
        }
    }

    #[test]
    fn line_breaks_inside_a_multiline_value_are_not_flagged() {
        assert_clean("first line\nsecond line");
        assert_clean("a\n\n\nb");
    }

    #[test]
    fn a_multiline_values_single_final_newline_is_part_of_the_text() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n";
        assert_clean(pem);
        assert_eq!(trim_ends(pem), pem);
    }

    #[test]
    fn a_single_line_values_trailing_newline_is_flagged() {
        assert_eq!(
            single("token\n"),
            (
                CharacterKind::TrailingWhitespace,
                HiddenCharacter::Char('\n'),
                vec![(6, 1)]
            )
        );
        assert_eq!(trim_ends("token\n"), "token");
    }

    #[test]
    fn a_blank_line_after_a_multiline_value_is_flagged_with_its_final_newline() {
        assert_eq!(
            single("a\nb\n\n"),
            (
                CharacterKind::TrailingWhitespace,
                HiddenCharacter::Char('\n'),
                vec![(4, 2)]
            )
        );
        assert_eq!(trim_ends("a\nb\n\n"), "a\nb");
    }

    #[test]
    fn spaces_before_a_multiline_values_final_newline_are_flagged() {
        let found = findings("a\nb  \n");
        assert_eq!(
            found,
            vec![
                (
                    CharacterKind::TrailingWhitespace,
                    HiddenCharacter::Char(' '),
                    2,
                    vec![(4, 2)]
                ),
                (
                    CharacterKind::TrailingWhitespace,
                    HiddenCharacter::Char('\n'),
                    1,
                    vec![(6, 1)]
                ),
            ]
        );
    }

    #[test]
    fn whitespace_at_either_end_is_flagged_by_kind() {
        assert_eq!(
            single(" token"),
            (
                CharacterKind::LeadingWhitespace,
                HiddenCharacter::Char(' '),
                vec![(1, 1)]
            )
        );
        assert_eq!(
            single("token\t"),
            (
                CharacterKind::TrailingWhitespace,
                HiddenCharacter::Char('\t'),
                vec![(6, 1)]
            )
        );
        assert_eq!(
            single("\ntoken"),
            (
                CharacterKind::LeadingWhitespace,
                HiddenCharacter::Char('\n'),
                vec![(1, 1)]
            )
        );
        assert_eq!(
            single("token\u{A0}"),
            (
                CharacterKind::TrailingWhitespace,
                HiddenCharacter::Char('\u{A0}'),
                vec![(6, 1)]
            )
        );
    }

    #[test]
    fn a_value_of_only_whitespace_is_all_leading() {
        assert_eq!(
            single("   "),
            (
                CharacterKind::LeadingWhitespace,
                HiddenCharacter::Char(' '),
                vec![(1, 3)]
            )
        );
        assert_eq!(trim_ends("   "), "");
    }

    #[test]
    fn zero_width_and_format_characters_are_flagged_anywhere() {
        for character in [
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{2060}',
            '\u{FEFF}',
            '\u{AD}',
            '\u{34F}',
            '\u{180E}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{115F}',
            '\u{2062}',
            '\u{FFF9}',
            '\u{1D173}',
            '\u{1BCA0}',
            '\u{17B4}',
        ] {
            for (value, position) in [
                (format!("{character}token"), 1),
                (format!("to{character}ken"), 3),
                (format!("token{character}"), 6),
            ] {
                assert_eq!(
                    single(&value),
                    (
                        CharacterKind::Invisible,
                        HiddenCharacter::Char(character),
                        vec![(position, 1)]
                    ),
                    "{value:?}"
                );
            }
        }
    }

    #[test]
    fn a_byte_order_mark_at_the_start_of_a_pasted_value_is_flagged() {
        let found = check_value_characters("\u{FEFF}sk_live_abc").expect("flagged");
        assert_eq!(
            found.characters[0].describe(),
            "\\u{feff} ZERO WIDTH NO-BREAK SPACE at character 1"
        );
        assert!(found.removable);
        assert!(!found.trimmable);
    }

    #[test]
    fn direction_controls_are_flagged() {
        for character in [
            '\u{61C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert_eq!(
                single(&format!("abc{character}def")),
                (
                    CharacterKind::Direction,
                    HiddenCharacter::Char(character),
                    vec![(4, 1)]
                )
            );
        }
    }

    #[test]
    fn spaces_other_than_the_plain_space_are_flagged_inside_a_value() {
        for character in [
            '\t', '\u{A0}', '\u{1680}', '\u{2000}', '\u{2005}', '\u{200A}', '\u{202F}', '\u{205F}',
            '\u{3000}', '\u{2800}',
        ] {
            assert_eq!(
                single(&format!("ab{character}cd")),
                (
                    CharacterKind::Space,
                    HiddenCharacter::Char(character),
                    vec![(3, 1)]
                )
            );
        }
    }

    #[test]
    fn control_characters_are_flagged() {
        for character in [
            '\u{0}', '\u{7}', '\u{8}', '\u{1B}', '\u{7F}', '\u{80}', '\u{9B}',
        ] {
            assert_eq!(
                single(&format!("ab{character}cd")),
                (
                    CharacterKind::Control,
                    HiddenCharacter::Char(character),
                    vec![(3, 1)]
                )
            );
        }
    }

    #[test]
    fn line_breaks_other_than_newline_are_flagged() {
        for character in ['\r', '\u{B}', '\u{C}', '\u{85}', '\u{2028}', '\u{2029}'] {
            assert_eq!(
                single(&format!("ab{character}cd")),
                (
                    CharacterKind::LineBreak,
                    HiddenCharacter::Char(character),
                    vec![(3, 1)]
                )
            );
        }
    }

    #[test]
    fn crlf_line_endings_in_a_multiline_value_flag_each_carriage_return() {
        let value = "line one\r\nline two\r\n";
        assert_eq!(
            single(value),
            (
                CharacterKind::LineBreak,
                HiddenCharacter::Char('\r'),
                vec![(9, 1), (19, 1)]
            )
        );
        assert_eq!(remove_hidden_characters(value), "line one\nline two\n");
        assert_eq!(trim_ends(value), value);
    }

    #[test]
    fn emoji_sequences_are_not_flagged() {
        for emoji in [
            "👨\u{200D}👩\u{200D}👧",
            "🏳\u{FE0F}\u{200D}🌈",
            "👩🏽\u{200D}💻",
            "❤\u{FE0F}",
            "↩\u{FE0E}",
            "1\u{FE0F}\u{20E3}",
            "👁\u{FE0F}\u{200D}🗨\u{FE0F}",
            "🐻\u{200D}❄\u{FE0F}",
            "🏴\u{200D}☠\u{FE0F}",
            "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
            "🏴\u{E0067}\u{E0062}\u{E0077}\u{E006C}\u{E0073}\u{E007F}",
        ] {
            assert_clean(emoji);
            assert_clean(&format!("deploy {emoji} done"));
        }
    }

    #[test]
    fn ordinary_non_latin_text_is_not_flagged() {
        for text in [
            "می\u{200C}خواهم",
            "کتاب\u{200C}ها",
            "मराठी",
            "क्\u{200D}ष",
            "क्\u{200C}ष",
            "ന്\u{200D}",
            "ශ්\u{200D}රී",
            "ರ\u{200D}್ಯ",
            "مرحبا بالعالم",
            "שלום עולם",
            "你好，世界",
            "葛\u{E0100}城市",
            "侮\u{FE00}辱",
            "こんにちは世界",
            "안녕하세요",
            "Привет, мир",
            "ᠮᠣᠩᠭᠣᠯ",
            "ᠠ\u{180B}",
            "ᠨᠠ\u{180E}ᠠ",
            "Ελληνικά",
        ] {
            assert_clean(text);
        }
    }

    #[test]
    fn joiners_outside_the_text_that_shapes_with_them_are_flagged() {
        for value in [
            "pass\u{200C}word",
            "pass\u{200D}word",
            "😀\u{200D}a",
            "👍\u{200D}",
            "a\u{200D}👍",
        ] {
            let (kind, character, _) = single(value);
            assert_eq!(kind, CharacterKind::Invisible, "{value:?}");
            assert!(
                matches!(character, HiddenCharacter::Char('\u{200C}' | '\u{200D}')),
                "{value:?}"
            );
        }
        assert_eq!(
            findings("👍\u{200D}\u{200D}👍")[0].3,
            vec![(2, 2)],
            "a second joiner in a row never joins"
        );
    }

    #[test]
    fn variation_selectors_need_a_base_they_vary() {
        assert_eq!(
            single("a\u{FE0F}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::VariationSelectors,
                vec![(2, 1)]
            )
        );
        assert_eq!(
            single("a\u{E0100}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::VariationSelectors,
                vec![(2, 1)]
            )
        );
        assert_eq!(
            single("😀\u{FE0F}\u{FE01}\u{E0105}\u{E01EF}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::VariationSelectors,
                vec![(3, 3)]
            ),
            "selectors after the first can only be hiding data"
        );
        assert_eq!(
            single("侮\u{FE00}\u{FE01}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::VariationSelectors,
                vec![(3, 1)]
            ),
            "one standardized selector after an ideograph is text; a second is not"
        );
        assert_eq!(
            single("a\u{FE00}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::VariationSelectors,
                vec![(2, 1)]
            )
        );
        assert_eq!(
            single("ᠠ\u{180B}\u{180C}"),
            (
                CharacterKind::Invisible,
                HiddenCharacter::Char('\u{180C}'),
                vec![(3, 1)]
            )
        );
    }

    #[test]
    fn tag_characters_are_flagged_as_one_group_outside_the_recommended_flags() {
        let texas = "🏴\u{E0075}\u{E0073}\u{E0074}\u{E0078}\u{E007F}";
        assert_eq!(
            single(texas),
            (
                CharacterKind::Invisible,
                HiddenCharacter::Tags,
                vec![(2, 5)]
            )
        );
        let hidden = "ok\u{E0001}\u{E0068}\u{E0069}";
        let found = check_value_characters(hidden).expect("flagged");
        assert_eq!(found.characters.len(), 1);
        let described = found.characters[0].describe();
        assert_eq!(described, "tag characters ×3 at characters 3–5");
        assert!(found.characters[0].character.escape().is_none());
        assert!(found.characters[0].character.code_point().is_none());
    }

    #[test]
    fn unassigned_default_ignorable_code_points_are_one_group() {
        let found = findings("a\u{E0080}b\u{2065}c\u{FFF0}");
        assert_eq!(
            found,
            vec![(
                CharacterKind::Invisible,
                HiddenCharacter::Unassigned,
                3,
                vec![(2, 1), (4, 1), (6, 1)]
            )]
        );
    }

    #[test]
    fn positions_count_characters_not_bytes_or_utf16_units() {
        assert_eq!(single("é😀\u{1F3FD}x\u{200B}").2, vec![(5, 1)]);
    }

    #[test]
    fn repeated_characters_are_counted_in_runs() {
        assert_eq!(
            findings("a\u{200B}\u{200B}b\u{200B}"),
            vec![(
                CharacterKind::Invisible,
                HiddenCharacter::Char('\u{200B}'),
                3,
                vec![(2, 2), (5, 1)]
            )]
        );
    }

    #[test]
    fn a_report_lists_at_most_its_limits_and_counts_the_rest() {
        let value: String =
            "\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}"
                .chars()
                .flat_map(|space| ['x', space])
                .collect::<String>()
                + "x";
        let found = check_value_characters(&value).expect("flagged");
        assert_eq!(found.characters.len(), MAX_LISTED_CHARACTERS);
        assert_eq!(found.more, 2);

        let scattered = "x\u{200B}".repeat(20) + "x";
        let found = check_value_characters(&scattered).expect("flagged");
        let character = &found.characters[0];
        assert_eq!(character.count, 20);
        assert_eq!(character.runs.len(), MAX_LISTED_RUNS);
        assert_eq!(
            character.describe(),
            "\\u{200b} ZERO WIDTH SPACE ×20 at characters 2, 4, 6, 8, 10, 12, 14, 16, …"
        );
    }

    #[test]
    fn descriptions_name_the_character_and_where_without_the_value() {
        let found = check_value_characters("  hunter2\u{200B}x\u{A0}\u{A0}y\n").expect("flagged");
        let described: Vec<String> = found
            .characters
            .iter()
            .map(FoundCharacter::describe)
            .collect();
        assert_eq!(
            described,
            vec![
                "\\u{20} SPACE ×2 at the start",
                "\\u{200b} ZERO WIDTH SPACE at character 10",
                "\\u{a0} NO-BREAK SPACE ×2 at characters 12–13",
                "\\n LINE FEED at the end",
            ]
        );
        for line in &described {
            assert!(!line.contains("hunter2"), "{line}");
        }
    }

    #[test]
    fn removing_hidden_characters_replaces_each_by_its_kind() {
        assert_eq!(
            remove_hidden_characters(" a\u{200B}b\u{A0}c\td\r\ne\u{2028}f\u{202E}g\u{1B}h "),
            " ab c d\ne\nfgh "
        );
        assert_eq!(
            remove_hidden_characters("a\rb"),
            "a\nb",
            "a lone carriage return breaks a line"
        );
        assert!(matches!(
            remove_hidden_characters("clean value"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            remove_hidden_characters(" only ends "),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn trimming_removes_only_the_flagged_ends() {
        assert_eq!(trim_ends("  a b \t\n"), "a b");
        assert_eq!(trim_ends("a\u{200B}"), "a\u{200B}");
        assert_eq!(
            trim_ends("\n-----BEGIN-----\nx\n-----END-----\n"),
            "-----BEGIN-----\nx\n-----END-----\n"
        );
    }

    #[test]
    fn removing_then_trimming_leaves_nothing_to_flag() {
        for value in [
            " \u{FEFF} token\u{200B} ",
            "\u{A0}a\u{2028}b\u{2029}",
            "a\r\nb\r\n",
            "x\u{E0061}\u{FE01}\u{2066}y\t",
            "ب\u{34F}\u{200C}ب",
            "\u{3000}\u{3164}",
        ] {
            let fixed = remove_hidden_characters(value);
            let fixed = trim_ends(&fixed);
            assert_clean(fixed);
        }
    }

    #[test]
    fn showing_a_value_escapes_each_flagged_character_and_marks_it_in_utf16() {
        let shown = show_hidden_characters("😀a\u{200B}b \n");
        assert_eq!(shown.text, "😀a\\u{200b}b\\u{20}\\n");
        assert_eq!(shown.marks, vec![3..11, 12..18, 18..20]);
        let pem = "a\nb\n";
        assert_eq!(show_hidden_characters(pem).text, pem);
        assert!(show_hidden_characters(pem).marks.is_empty());
    }

    /// The rule against Unicode's own data: inside a value, exactly the
    /// default-ignorable code points, the spaces other than U+0020, the
    /// controls other than `\n`, the line and paragraph separators, the
    /// interlinear annotation characters and the blank Braille cell are
    /// flagged, and each one reported by itself has a name.
    #[test]
    fn every_code_point_is_flagged_exactly_when_unicode_says_it_hides() {
        let ignorable = CodePointSetData::new::<DefaultIgnorableCodePoint>();
        let categories = CodePointMapData::<GeneralCategory>::new();
        let mut value = String::with_capacity(8);
        for character in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let category = categories.get(character);
            let expected = ignorable.contains(character)
                || (category == GeneralCategory::SpaceSeparator && character != ' ')
                || (category == GeneralCategory::Control && character != '\n')
                || matches!(
                    category,
                    GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
                )
                || matches!(character, '\u{FFF9}'..='\u{FFFB}' | '\u{2800}');
            value.clear();
            value.push('a');
            value.push(character);
            value.push('a');
            let found = check_value_characters(&value);
            assert_eq!(found.is_some(), expected, "U+{:04X}", u32::from(character));
            if let Some(found) = found {
                assert_eq!(
                    found.characters[0].runs,
                    vec![CharacterRun {
                        position: 2,
                        count: 1
                    }]
                );
                if let HiddenCharacter::Char(found) = found.characters[0].character {
                    assert!(
                        !unicode_name(found).is_empty(),
                        "U+{:04X} has no name",
                        u32::from(found)
                    );
                }
            }
        }
    }

    #[test]
    fn every_whitespace_character_at_an_end_has_a_name() {
        for character in (0..=u32::from(char::MAX))
            .filter_map(char::from_u32)
            .filter(|character| character.is_whitespace())
        {
            assert!(
                !unicode_name(character).is_empty(),
                "U+{:04X}",
                u32::from(character)
            );
        }
    }

    #[test]
    fn a_large_value_is_checked_in_one_pass() {
        let hidden = "\u{200B}".repeat(4 * 1024 * 1024);
        let found = check_value_characters(&hidden).expect("flagged");
        assert_eq!(found.characters[0].count, 4 * 1024 * 1024);
        assert_eq!(
            found.characters[0].runs,
            vec![CharacterRun {
                position: 1,
                count: 4 * 1024 * 1024
            }]
        );

        let scattered = "ab\u{200B}".repeat(1024 * 1024);
        let found = check_value_characters(&scattered).expect("flagged");
        assert_eq!(found.characters[0].count, 1024 * 1024);
        assert_eq!(found.characters[0].runs.len(), MAX_LISTED_RUNS);
        assert_eq!(remove_hidden_characters(&scattered).len(), 2 * 1024 * 1024);

        let persian = "می\u{200C}".repeat(1024 * 1024) + "می";
        assert_clean(&persian);
        let emoji = "👨\u{200D}".repeat(1024 * 1024) + "👧";
        assert_clean(&emoji);
    }
}
