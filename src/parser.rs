use std::path::PathBuf;

use crate::ast::*;
use crate::error::{ArgentError, Result};
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
            if self.check_ident("import") {
                module.imports.push(self.parse_import()?);
            } else if self.check_ident("const") {
                module.consts.push(self.parse_const()?);
            } else if self.check_ident("state") {
                module.states.push(self.parse_state()?);
            } else if self.check_ident("fn") {
                module.functions.push(self.parse_function()?);
            } else if self.check_ident("actor") {
                if self.peek_ident(1, "enum") {
                    module.actor_enums.push(self.parse_actor_enum()?);
                } else {
                    module.actors.push(self.parse_actor()?);
                }
            } else if self.check_ident("app") {
                module.apps.push(self.parse_app()?);
            } else {
                return Err(self.error(format!("expected top-level declaration, found {}", self.describe_current())));
            }
        }

        Ok(module)
    }

    fn parse_import(&mut self) -> Result<Import> {
        self.expect_ident("import")?;
        if self.consume_ident("actor") {
            let name = self.expect_any_ident()?;
            self.expect_ident("from")?;
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
        self.expect_ident("const")?;
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
        self.expect_ident("state")?;
        let name = self.expect_any_ident()?;
        let expands = if self.consume_ident("expands") { Some(self.expect_any_ident()?) } else { None };
        self.expect_symbol('{')?;
        let mut fields = Vec::new();
        let mut digest_expansions = Vec::new();
        while !self.check_symbol('}') {
            if expands.is_some() {
                self.expect_ident("expand")?;
                let field = self.expect_any_ident()?;
                self.expect_ident("as")?;
                let state = self.expect_any_ident()?;
                self.expect_symbol(';')?;
                digest_expansions.push(StateDigestExpansionDecl { field, state });
            } else {
                let ty = self.parse_type()?;
                let name = self.expect_any_ident()?;
                self.expect_symbol(';')?;
                fields.push(FieldDecl { ty, name });
            }
        }
        self.expect_symbol('}')?;
        let expansion = expands.map(|base| StateExpansionDecl { base, digests: digest_expansions });
        Ok(StateDecl { name, fields, expansion })
    }

    fn parse_function(&mut self) -> Result<FunctionDecl> {
        self.expect_ident("fn")?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        self.expect_arrow()?;
        let return_ty = self.parse_type()?;
        let body = self.consume_block_text()?;
        Ok(FunctionDecl { name, params, return_ty, body })
    }

    fn parse_actor(&mut self) -> Result<ActorDecl> {
        self.expect_ident("actor")?;
        let name = self.expect_any_ident()?;
        self.expect_ident("owns")?;
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
        self.expect_ident("actor")?;
        self.expect_ident("enum")?;
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
        if self.check_ident("entry") {
            self.parse_entry()
        } else if self.check_ident("delegate") {
            self.parse_delegate()
        } else {
            Err(self.error(format!("expected `entry` or `delegate`, found {}", self.describe_current())))
        }
    }

    fn parse_entry(&mut self) -> Result<EntryDecl> {
        self.expect_ident("entry")?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        let (observes, consumes) = self.parse_entry_clauses()?;
        self.expect_ident("emits")?;
        let emits = self.parse_emits()?;
        let body = self.consume_block_text()?;
        let route_analysis = analyze_routes(&body).map_err(|err| ArgentError::at(&self.path, err.message))?;
        Ok(EntryDecl {
            kind: EntryKind::Leader,
            name,
            params,
            consumes,
            observes,
            emits,
            body,
            routes: route_analysis.routes,
            terminal_route_sets: route_analysis.terminal_route_sets,
        })
    }

    fn parse_delegate(&mut self) -> Result<EntryDecl> {
        self.expect_ident("delegate")?;
        let name = self.expect_any_ident()?;
        let params = self.parse_param_list()?;
        let (observes, consumes) = self.parse_entry_clauses()?;
        let body = self.consume_block_text()?;
        let route_analysis = analyze_routes(&body).map_err(|err| ArgentError::at(&self.path, err.message))?;
        Ok(EntryDecl {
            kind: EntryKind::Delegate,
            name,
            params,
            consumes,
            observes,
            emits: EmitSpec::None,
            body,
            routes: route_analysis.routes,
            terminal_route_sets: route_analysis.terminal_route_sets,
        })
    }

    fn parse_app(&mut self) -> Result<AppDecl> {
        self.expect_ident("app")?;
        let name = self.expect_any_ident()?;
        self.expect_symbol('{')?;
        let mut actors = Vec::new();
        while !self.check_symbol('}') {
            if self.consume_ident("actor") {
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
            let name = self.expect_any_ident()?;
            self.expect_symbol(':')?;
            let ty = self.parse_type_from_current()?;
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
        self.expect_ident("consumes")?;
        self.expect_symbol('{')?;
        let mut consumes = Vec::new();
        while !self.check_symbol('}') {
            let name = self.expect_any_ident()?;
            self.expect_symbol(':')?;
            let actor = self.expect_any_ident()?;
            self.expect_symbol(';')?;
            consumes.push(ConsumeDecl { name, actor });
        }
        self.expect_symbol('}')?;
        Ok(consumes)
    }

    fn parse_entry_clauses(&mut self) -> Result<(Vec<ObserveDecl>, Vec<ConsumeDecl>)> {
        let mut observes = Vec::new();
        let mut consumes = Vec::new();
        let mut parsed_consumes = false;
        loop {
            if self.check_ident("observes") {
                observes.push(self.parse_observes()?);
            } else if self.check_ident("consumes") {
                if parsed_consumes {
                    return Err(self.error("entry declares `consumes` more than once"));
                }
                consumes = self.parse_consumes()?;
                parsed_consumes = true;
            } else {
                break;
            }
        }
        Ok((observes, consumes))
    }

    fn parse_observes(&mut self) -> Result<ObserveDecl> {
        self.expect_ident("observes")?;
        let name = self.expect_any_ident()?;
        self.expect_ident("by")?;
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
            if self.check_ident("inputs") {
                if inputs.is_some() {
                    return Err(self.error("observes clause declares `inputs` more than once"));
                }
                inputs = Some(self.parse_observed_actor_list("inputs")?);
            } else if self.check_ident("outputs") {
                if outputs.is_some() {
                    return Err(self.error("observes clause declares `outputs` more than once"));
                }
                outputs = Some(self.parse_observed_actor_list("outputs")?);
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
            let (actor, open_state) = if self.consume_ident("actor") {
                if section != "inputs" {
                    return Err(self.error("open observed actor bindings are only declared in `inputs`"));
                }
                self.expect_symbol('<')?;
                let state = self.expect_any_ident()?;
                self.expect_symbol('>')?;
                self.expect_ident("as")?;
                (self.expect_any_ident()?, Some(state))
            } else {
                (self.take_observed_actor_target()?, None)
            };
            self.expect_symbol(';')?;
            actors.push(ObservedActorDecl { name, actor, open_state });
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
                TokenKind::Symbol('}') | TokenKind::Symbol(')') | TokenKind::Symbol(']') | TokenKind::Symbol('>') => {
                    depth = depth.saturating_sub(1);
                    self.advance();
                }
                TokenKind::Symbol(';') if depth == 0 => {
                    let text = self.source[start..token.span.start].trim().to_string();
                    if text.is_empty() {
                        return Err(self.error("observed actor target is empty"));
                    }
                    return Ok(text);
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

    fn parse_type_from_current(&mut self) -> Result<TypeRef> {
        self.parse_type()
    }

    fn parse_type_tail(&mut self, name: String) -> Result<TypeRef> {
        if name == "actor" && self.consume_symbol('<') {
            let state = self.expect_any_ident()?;
            self.expect_symbol('>')?;
            Ok(TypeRef::actor_handle(state))
        } else if self.consume_symbol('[') {
            let len = self.expect_number()?.parse::<usize>().map_err(|_| self.error("invalid array length"))?;
            self.expect_symbol(']')?;
            Ok(TypeRef::array(name, len))
        } else {
            Ok(TypeRef::new(name))
        }
    }

    fn parse_emits(&mut self) -> Result<EmitSpec> {
        if self.consume_ident("none") {
            Ok(EmitSpec::None)
        } else if self.consume_ident("one") {
            let actors = self.parse_actor_union_until_body()?;
            Ok(EmitSpec::One { actors })
        } else if self.check_symbol('{') {
            self.expect_symbol('{')?;
            let mut outputs = Vec::new();
            while !self.check_symbol('}') {
                let name = self.expect_any_ident()?;
                self.expect_symbol(':')?;
                let actors = self.parse_actor_union_until_at()?;
                let auth_index = if self.consume_ident("at") {
                    self.expect_ident("auth")?;
                    self.expect_symbol('[')?;
                    let auth_index = self.expect_number()?.parse::<usize>().map_err(|_| self.error("invalid auth index"))?;
                    self.expect_symbol(']')?;
                    auth_index
                } else {
                    outputs.len()
                };
                self.expect_symbol(';')?;
                outputs.push(EmitOutput { name, actors, auth_index });
            }
            self.expect_symbol('}')?;
            Ok(EmitSpec::Outputs(outputs))
        } else {
            Err(self.error(format!("expected emits spec, found {}", self.describe_current())))
        }
    }

    fn parse_actor_union_until_body(&mut self) -> Result<Vec<String>> {
        let mut actors = Vec::new();
        actors.push(self.expect_any_ident()?);
        while self.consume_symbol('|') {
            actors.push(self.expect_any_ident()?);
        }
        Ok(actors)
    }

    fn parse_actor_union_until_at(&mut self) -> Result<Vec<String>> {
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
