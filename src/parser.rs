use std::path::PathBuf;

use crate::ast::*;
use crate::error::{ArgentError, Result};
use crate::language::word;
use crate::lexer::{Token, TokenKind, lex};
use crate::routes::analyze_routes;

pub fn parse_module(path: PathBuf, source: String) -> Result<Module> {
    let tokens = lex(&source).map_err(|err| ArgentError { path: Some(path.clone()), message: err.message })?;
    Parser { path, source, tokens, pos: 0 }.parse_module()
}

struct Parser {
    path: PathBuf,
    source: String,
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn parse_module(mut self) -> Result<Module> {
        let mut module = Module {
            path: self.path.clone(),
            imports: Vec::new(),
            consts: Vec::new(),
            states: Vec::new(),
            functions: Vec::new(),
            actors: Vec::new(),
            actor_enums: Vec::new(),
            apps: Vec::new(),
        };

        while !self.is_eof() {
            if self.check_ident(word::IMPORT) {
                module.imports.push(self.parse_import()?);
            } else if self.check_ident(word::CONST) {
                module.consts.push(self.parse_const()?);
            } else if self.check_ident(word::STATE) {
                module.states.push(self.parse_state()?);
            } else if self.check_ident(word::FN) {
                module.functions.push(self.parse_function()?);
            } else if self.check_ident(word::ACTOR) {
                if self.peek_ident(1, word::ENUM) {
                    module.actor_enums.push(self.parse_actor_enum()?);
                } else {
                    module.actors.push(self.parse_actor()?);
                }
            } else if self.check_ident(word::APP) {
                module.apps.push(self.parse_app()?);
            } else {
                return Err(self.error(format!("expected top-level declaration, found {}", self.describe_current())));
            }
        }

        Ok(module)
    }

    fn parse_import(&mut self) -> Result<Import> {
        self.expect_ident(word::IMPORT)?;
        if self.consume_ident(word::ACTOR) {
            let name = self.expect_any_ident()?;
            self.expect_ident(word::FROM)?;
            let path = self.expect_string()?;
            self.expect_symbol(';')?;
            Ok(Import::Actor { name, path })
        } else {
            let path = self.expect_string()?;
            self.expect_symbol(';')?;
            Ok(Import::Module { path })
        }
    }

    fn parse_const(&mut self) -> Result<ConstDecl> {
        self.expect_ident(word::CONST)?;
        let ty = self.parse_type()?;
        let name = self.expect_any_ident()?;
        self.expect_symbol('=')?;
        let value_start = self.current().span.start;
        while !self.check_symbol(';') && !self.is_eof() {
            self.advance();
        }
        let value_end = self.current().span.start;
        self.expect_symbol(';')?;
        Ok(ConstDecl { ty, name, value: self.source[value_start..value_end].trim().to_string() })
    }

    fn parse_state(&mut self) -> Result<StateDecl> {
        self.expect_ident(word::STATE)?;
        let name = self.expect_any_ident()?;
        let expands = if self.consume_ident(word::EXPANDS) { Some(self.expect_any_ident()?) } else { None };
        self.expect_symbol('{')?;
        let mut fields = Vec::new();
        let mut digest_expansions = Vec::new();
        while !self.check_symbol('}') {
            if expands.is_some() {
                let field = self.expect_any_ident()?;
                self.expect_symbol(':')?;
                let state = self.expect_any_ident()?;
                self.expect_symbol(';')?;
                digest_expansions.push(StateDigestExpansionDecl { field, state });
            } else if self.consume_ident(word::VIRTUAL) {
                let name = self.expect_any_ident()?;
                self.expect_symbol(';')?;
                fields.push(FieldDecl { ty: TypeRef::array("byte", 32), name, virtual_slot: true });
            } else {
                let ty = self.parse_type()?;
                let name = self.expect_any_ident()?;
                self.expect_symbol(';')?;
                fields.push(FieldDecl { ty, name, virtual_slot: false });
            }
        }
        self.expect_symbol('}')?;
        let expansion = expands.map(|base| StateExpansionDecl { base, digests: digest_expansions });
        Ok(StateDecl { name, fields, expansion })
    }

    fn parse_function(&mut self) -> Result<FunctionDecl> {
        self.expect_ident(word::FN)?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        self.expect_arrow()?;
        let return_ty = self.parse_type()?;
        let body = self.consume_block_text()?;
        Ok(FunctionDecl { name, params, return_ty, body })
    }

    fn parse_actor(&mut self) -> Result<ActorDecl> {
        self.expect_ident(word::ACTOR)?;
        let name = self.expect_any_ident()?;
        self.expect_ident(word::OWNS)?;
        let state = self.expect_any_ident()?;
        self.expect_symbol('{')?;
        let mut entries = Vec::new();
        while !self.check_symbol('}') {
            entries.push(self.parse_actor_item()?);
        }
        self.expect_symbol('}')?;
        Ok(ActorDecl { name, state, entries })
    }

    fn parse_actor_enum(&mut self) -> Result<ActorEnumDecl> {
        self.expect_ident(word::ACTOR)?;
        self.expect_ident(word::ENUM)?;
        let name = self.expect_any_ident()?;
        self.expect_symbol('{')?;
        let mut variants = Vec::new();
        while !self.check_symbol('}') {
            variants.push(self.expect_any_ident()?);
            if self.consume_symbol(';') || self.consume_symbol(',') {
                continue;
            }
            if !self.check_symbol('}') {
                return Err(self.error(format!("expected `;`, `,`, or `}}`, found {}", self.describe_current())));
            }
        }
        self.expect_symbol('}')?;
        Ok(ActorEnumDecl { name, variants })
    }

    fn parse_actor_item(&mut self) -> Result<EntryDecl> {
        if self.check_ident(word::ENTRY) {
            self.parse_entry()
        } else if self.check_ident(word::DELEGATE) {
            self.parse_delegate()
        } else {
            Err(self.error(format!("expected `entry` or `delegate`, found {}", self.describe_current())))
        }
    }

    fn parse_entry(&mut self) -> Result<EntryDecl> {
        self.expect_ident(word::ENTRY)?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        let (observes, consumes, spawns) = self.parse_entry_clauses()?;
        self.expect_ident(word::EMITS)?;
        let emits = self.parse_emits()?;
        let body = self.consume_block_text()?;
        let route_analysis = analyze_routes(&body).map_err(|err| ArgentError::at(&self.path, err.message))?;
        Ok(EntryDecl {
            kind: EntryKind::Leader,
            name,
            params,
            consumes,
            observes,
            spawns,
            emits,
            body,
            routes: route_analysis.routes,
            terminal_route_sets: route_analysis.terminal_route_sets,
        })
    }

    fn parse_delegate(&mut self) -> Result<EntryDecl> {
        self.expect_ident(word::DELEGATE)?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        let (observes, consumes, spawns) = self.parse_entry_clauses()?;
        let body = self.consume_block_text()?;
        let route_analysis = analyze_routes(&body).map_err(|err| ArgentError::at(&self.path, err.message))?;
        Ok(EntryDecl {
            kind: EntryKind::Delegate,
            name,
            params,
            consumes,
            observes,
            spawns,
            emits: EmitSpec::None,
            body,
            routes: route_analysis.routes,
            terminal_route_sets: route_analysis.terminal_route_sets,
        })
    }

    fn parse_app(&mut self) -> Result<AppDecl> {
        self.expect_ident(word::APP)?;
        let name = self.expect_any_ident()?;
        self.expect_symbol('{')?;
        let mut actors = Vec::new();
        while !self.check_symbol('}') {
            if self.consume_ident(word::ACTOR) {
                actors.push(self.expect_any_ident()?);
                self.expect_symbol(';')?;
            } else {
                return Err(self.error(format!("expected `actor`, found {}", self.describe_current())));
            }
        }
        self.expect_symbol('}')?;
        Ok(AppDecl { name, actors })
    }

    fn parse_param_list(&mut self) -> Result<Vec<ParamDecl>> {
        self.expect_symbol('(')?;
        let mut params = Vec::new();
        while !self.check_symbol(')') {
            let ty = self.parse_type()?;
            let name = self.expect_any_ident()?;
            params.push(ParamDecl { name, ty });
            if self.consume_symbol(',') {
                continue;
            }
            break;
        }
        self.expect_symbol(')')?;
        Ok(params)
    }

    fn parse_consumes(&mut self) -> Result<Vec<ConsumeDecl>> {
        self.expect_ident(word::CONSUMES)?;
        self.expect_symbol('{')?;
        let mut consumes = Vec::new();
        while !self.check_symbol('}') {
            let name = self.expect_any_ident()?;
            self.expect_symbol(':')?;
            let actor = self.expect_any_ident()?;
            consumes.push(ConsumeDecl { name, actor });
            self.expect_list_separator_or_end('}')?;
        }
        self.expect_symbol('}')?;
        Ok(consumes)
    }

    fn parse_entry_clauses(&mut self) -> Result<(Vec<ObserveDecl>, Vec<ConsumeDecl>, Vec<SpawnDecl>)> {
        let mut observes = Vec::new();
        let mut consumes = Vec::new();
        let mut spawns = Vec::new();
        let mut parsed_consumes = false;
        loop {
            if self.check_ident(word::OBSERVES) {
                observes.push(self.parse_observes()?);
            } else if self.check_ident(word::SPAWNS) {
                spawns.push(self.parse_spawns()?);
            } else if self.check_ident(word::CONSUMES) {
                if parsed_consumes {
                    return Err(self.error("entry declares `consumes` more than once"));
                }
                consumes = self.parse_consumes()?;
                parsed_consumes = true;
            } else {
                break;
            }
        }
        Ok((observes, consumes, spawns))
    }

    fn parse_spawns(&mut self) -> Result<SpawnDecl> {
        self.expect_ident(word::SPAWNS)?;
        let name = self.expect_any_ident()?;
        self.expect_ident(word::BY)?;
        let covenant = self.expect_any_ident()?;
        self.expect_symbol('{')?;
        self.expect_ident(word::OUTPUTS)?;
        self.expect_symbol('{')?;
        let mut outputs = Vec::new();
        while !self.check_symbol('}') {
            let name = self.expect_any_ident()?;
            self.expect_symbol(':')?;
            let actor = self.take_observed_actor_target()?;
            outputs.push(SpawnOutputDecl { name, actor, group_index: outputs.len() });
            self.expect_list_separator_or_end('}')?;
        }
        self.expect_symbol('}')?;
        self.expect_symbol('}')?;
        Ok(SpawnDecl { name, covenant, outputs })
    }

    fn parse_observes(&mut self) -> Result<ObserveDecl> {
        self.expect_ident(word::OBSERVES)?;
        let name = self.expect_any_ident()?;
        self.expect_ident(word::BY)?;
        let covenant_expr_start = self.current().span.start;
        while !self.check_symbol('{') && !self.is_eof() {
            self.advance();
        }
        let covenant_expr = self.source[covenant_expr_start..self.current().span.start].trim().to_string();
        if covenant_expr.is_empty() {
            return Err(self.error("observes clause has an empty covenant expression"));
        }

        self.expect_symbol('{')?;
        let mut inputs = None;
        let mut outputs = None;
        while !self.check_symbol('}') {
            if self.check_ident(word::INPUTS) {
                if inputs.is_some() {
                    return Err(self.error("observes clause declares `inputs` more than once"));
                }
                inputs = Some(self.parse_observed_actor_list(word::INPUTS)?);
            } else if self.check_ident(word::OUTPUTS) {
                if outputs.is_some() {
                    return Err(self.error("observes clause declares `outputs` more than once"));
                }
                outputs = Some(self.parse_observed_actor_list(word::OUTPUTS)?);
            } else {
                return Err(self.error(format!("expected `inputs` or `outputs`, found {}", self.describe_current())));
            }
        }
        self.expect_symbol('}')?;

        Ok(ObserveDecl { name, covenant_expr, inputs: inputs.unwrap_or_default(), outputs: outputs.unwrap_or_default() })
    }

    fn parse_observed_actor_list(&mut self, section: &str) -> Result<Vec<ObservedActorDecl>> {
        self.expect_ident(section)?;
        self.expect_symbol('{')?;
        let mut actors = Vec::new();
        while !self.check_symbol('}') {
            let name = self.expect_any_ident()?;
            self.expect_symbol(':')?;
            let (actor, open_state) = if self.consume_ident(word::ACTOR_TYPE) {
                if section != word::INPUTS {
                    return Err(self.error("open observed actor bindings are only declared in `inputs`"));
                }
                self.expect_symbol('<')?;
                let state = self.expect_any_ident()?;
                self.expect_symbol('>')?;
                self.expect_ident(word::AS)?;
                (self.expect_any_ident()?, Some(state))
            } else {
                (self.take_observed_actor_target()?, None)
            };
            actors.push(ObservedActorDecl { name, actor, open_state });
            self.expect_list_separator_or_end('}')?;
        }
        self.expect_symbol('}')?;
        Ok(actors)
    }

    fn take_observed_actor_target(&mut self) -> Result<String> {
        let start = self.current().span.start;
        let mut depth = 0usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol('{') | TokenKind::Symbol('(') | TokenKind::Symbol('[') | TokenKind::Symbol('<') => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol(',' | '}' | ';') if depth == 0 => {
                    let text = self.source[start..token.span.start].trim().to_string();
                    if text.is_empty() {
                        return Err(self.error("observed actor target is empty"));
                    }
                    return Ok(text);
                }
                TokenKind::Symbol('}') | TokenKind::Symbol(')') | TokenKind::Symbol(']') | TokenKind::Symbol('>') => {
                    depth = depth.saturating_sub(1);
                    self.advance();
                }
                _ => self.advance(),
            }
        }
        Err(self.error("unterminated observed actor target"))
    }

    fn parse_type(&mut self) -> Result<TypeRef> {
        let name = self.expect_any_ident()?;
        self.parse_type_tail(name)
    }

    fn parse_type_tail(&mut self, name: String) -> Result<TypeRef> {
        if name == word::ACTOR_TYPE && self.consume_symbol('<') {
            let state = self.expect_any_ident()?;
            self.expect_symbol('>')?;
            Ok(TypeRef::actor_type(state))
        } else if self.consume_symbol('[') {
            if self.consume_symbol(']') {
                return Ok(TypeRef::dynamic_array(name));
            }
            let len = self.expect_number()?.parse::<usize>().map_err(|_| self.error("invalid array length"))?;
            self.expect_symbol(']')?;
            Ok(TypeRef::array(name, len))
        } else {
            Ok(TypeRef::new(name))
        }
    }

    fn parse_emits(&mut self) -> Result<EmitSpec> {
        if self.consume_ident(word::NONE) {
            Ok(EmitSpec::None)
        } else if self.consume_ident(word::ONE) {
            let actors = self.parse_actor_union_until_body()?;
            Ok(EmitSpec::One { actors })
        } else if self.check_symbol('{') {
            self.expect_symbol('{')?;
            let mut outputs = Vec::new();
            while !self.check_symbol('}') {
                let name = self.expect_any_ident()?;
                self.expect_symbol(':')?;
                let actors = self.parse_actor_union()?;
                let auth_index = outputs.len();
                outputs.push(EmitOutput { name, actors, auth_index });
                self.expect_list_separator_or_end('}')?;
            }
            self.expect_symbol('}')?;
            Ok(EmitSpec::Outputs(outputs))
        } else {
            Err(self.error(format!("expected emits spec, found {}", self.describe_current())))
        }
    }

    fn parse_actor_union_until_body(&mut self) -> Result<Vec<String>> {
        self.parse_actor_union()
    }

    fn parse_actor_union(&mut self) -> Result<Vec<String>> {
        let mut actors = Vec::new();
        actors.push(self.expect_any_ident()?);
        while self.consume_symbol('|') {
            actors.push(self.expect_any_ident()?);
        }
        Ok(actors)
    }

    fn consume_block_text(&mut self) -> Result<String> {
        self.expect_symbol('{')?;
        let start = self.previous().span.end;
        let mut depth = 1usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol('{') => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol('}') => {
                    depth -= 1;
                    if depth == 0 {
                        let end = token.span.start;
                        self.advance();
                        return Ok(self.source[start..end].to_string());
                    }
                    self.advance();
                }
                _ => self.advance(),
            }
        }
        Err(self.error("unterminated block"))
    }

    fn expect_ident(&mut self, expected: &str) -> Result<()> {
        match &self.current().kind {
            TokenKind::Ident(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}`, found {}", self.describe_current()))),
        }
    }

    fn consume_ident(&mut self, expected: &str) -> bool {
        match &self.current().kind {
            TokenKind::Ident(actual) if actual == expected => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn peek_ident(&self, offset: usize, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos + offset).map(|token| &token.kind), Some(TokenKind::Ident(actual)) if actual == expected)
    }

    fn expect_any_ident(&mut self) -> Result<String> {
        match self.current().kind.clone() {
            TokenKind::Ident(name) => {
                self.advance();
                Ok(name)
            }
            _ => Err(self.error(format!("expected identifier, found {}", self.describe_current()))),
        }
    }

    fn check_ident(&self, expected: &str) -> bool {
        matches!(&self.current().kind, TokenKind::Ident(actual) if actual == expected)
    }

    fn expect_number(&mut self) -> Result<String> {
        match self.current().kind.clone() {
            TokenKind::Number(value) => {
                self.advance();
                Ok(value)
            }
            _ => Err(self.error(format!("expected number, found {}", self.describe_current()))),
        }
    }

    fn expect_string(&mut self) -> Result<String> {
        match self.current().kind.clone() {
            TokenKind::Str(value) => {
                self.advance();
                Ok(value)
            }
            _ => Err(self.error(format!("expected string, found {}", self.describe_current()))),
        }
    }

    fn expect_symbol(&mut self, expected: char) -> Result<()> {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}`, found {}", self.describe_current()))),
        }
    }

    fn consume_symbol(&mut self, expected: char) -> bool {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn expect_list_separator_or_end(&mut self, end: char) -> Result<()> {
        if self.consume_symbol(',') || self.check_symbol(end) {
            Ok(())
        } else {
            Err(self.error(format!("expected `,` or `{end}`, found {}", self.describe_current())))
        }
    }

    fn check_symbol(&self, expected: char) -> bool {
        matches!(self.current().kind, TokenKind::Symbol(actual) if actual == expected)
    }

    fn expect_arrow(&mut self) -> Result<()> {
        match self.current().kind {
            TokenKind::Arrow => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `->`, found {}", self.describe_current()))),
        }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn previous(&self) -> &Token {
        &self.tokens[self.pos - 1]
    }

    fn advance(&mut self) {
        if !self.is_eof() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        matches!(self.current().kind, TokenKind::Eof)
    }

    fn describe_current(&self) -> String {
        match &self.current().kind {
            TokenKind::Ident(value) => format!("identifier `{value}`"),
            TokenKind::Number(value) => format!("number `{value}`"),
            TokenKind::Str(value) => format!("string \"{value}\""),
            TokenKind::Arrow => "`->`".to_string(),
            TokenKind::LeftArrow => "`<-`".to_string(),
            TokenKind::Symbol(value) => format!("`{value}`"),
            TokenKind::Eof => "end of file".to_string(),
        }
    }

    fn error(&self, message: impl Into<String>) -> ArgentError {
        ArgentError::at(&self.path, format!("{} at byte {}", message.into(), self.current().span.start))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_module;
    use crate::ast::TypeRef;

    #[test]
    fn parses_type_first_function_entry_and_delegate_parameters() {
        let module = parse_module(
            PathBuf::from("params.ag"),
            r#"
            state State {
                int value;
            }

            fn helper(byte[32] owner, int amount,) -> int {
                return amount;
            }

            actor Actor owns State {
                entry update(int amount, actor_type<State> target,) emits none {}
                delegate verify(sig owner_sig,) consumes {
                    leader: Actor,
                } {}
            }
            "#
            .to_string(),
        )
        .expect("type-first parameters parse");

        assert_eq!(module.functions[0].params[0].name, "owner");
        assert_eq!(module.functions[0].params[0].ty, TypeRef::array("byte", 32));
        assert_eq!(module.functions[0].params[1].name, "amount");
        assert_eq!(module.functions[0].params[1].ty, TypeRef::new("int"));

        let actor = &module.actors[0];
        assert_eq!(actor.entries[0].params[0].name, "amount");
        assert_eq!(actor.entries[0].params[0].ty, TypeRef::new("int"));
        assert_eq!(actor.entries[0].params[1].name, "target");
        assert_eq!(actor.entries[0].params[1].ty, TypeRef::actor_type("State"));
        assert_eq!(actor.entries[1].params[0].name, "owner_sig");
        assert_eq!(actor.entries[1].params[0].ty, TypeRef::new("sig"));
    }

    #[test]
    fn rejects_name_first_parameters() {
        let err = parse_module(PathBuf::from("params.ag"), "fn helper(amount: int) -> int { return amount; }".to_string())
            .expect_err("name-first parameters must not parse");

        assert!(err.to_string().contains("expected identifier, found `:`"), "unexpected error: {err}");
    }

    #[test]
    fn parses_comma_separated_role_and_route_bindings() {
        let module = parse_module(
            PathBuf::from("bindings.ag"),
            r#"
            state State {
                int value;
            }

            actor Actor owns State {
                entry update()
                observes remote by remote_id {
                    inputs {
                        input: actor_type<State> as observed_actor,
                    }
                    outputs {
                        output: observed_actor
                    }
                }
                spawns child by child_id {
                    outputs {
                        first: Actor,
                        second: observed_actor
                    }
                }
                consumes {
                    peer: Actor,
                    other: Actor
                }
                emits {
                    first: Actor,
                    second: Actor
                } {
                    become {
                        first <- Actor(self.state),
                        second <- Actor(self.state)
                    };
                }
            }
            "#
            .to_string(),
        )
        .expect("comma-separated bindings parse");

        let entry = &module.actors[0].entries[0];
        assert_eq!(entry.observes[0].inputs.len(), 1);
        assert_eq!(entry.observes[0].outputs.len(), 1);
        assert_eq!(entry.spawns[0].outputs.len(), 2);
        assert_eq!(entry.consumes.len(), 2);
        assert!(matches!(&entry.emits, crate::ast::EmitSpec::Outputs(outputs) if outputs.len() == 2));
        assert_eq!(entry.routes.len(), 2);
    }

    #[test]
    fn rejects_semicolons_in_role_binding_lists() {
        for source in [
            r#"
                state State {}
                actor Actor owns State {
                    entry update() consumes { peer: Actor; } emits none {}
                }
            "#,
            r#"
                state State {}
                actor Actor owns State {
                    entry update() emits { next: Actor; } {}
                }
            "#,
            r#"
                state State {}
                actor Actor owns State {
                    entry update()
                    spawns child by child_id { outputs { next: Actor; } }
                    emits none {}
                }
            "#,
            r#"
                state State {}
                actor Actor owns State {
                    entry update()
                    observes remote by remote_id { inputs { peer: Actor; } }
                    emits none {}
                }
            "#,
        ] {
            let err = parse_module(PathBuf::from("bindings.ag"), source.to_string())
                .expect_err("semicolon-separated role bindings must not parse");
            assert!(err.to_string().contains("expected `,` or `}`"), "unexpected error: {err}");
        }
    }
}
