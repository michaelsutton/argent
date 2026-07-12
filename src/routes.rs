use crate::ast::RouteCall;
use crate::error::{ArgentError, Result};
use crate::language::word;
use crate::lexer::{Token, TokenKind, lex};

#[derive(Debug, Clone)]
pub struct RouteAnalysis {
    pub routes: Vec<RouteCall>,
    pub terminal_route_sets: Vec<Vec<RouteCall>>,
}

pub fn collect_routes(body: &str) -> Result<Vec<RouteCall>> {
    analyze_routes(body).map(|analysis| analysis.routes)
}

pub fn analyze_routes(body: &str) -> Result<RouteAnalysis> {
    let tokens = lex(body)?;
    let mut parser = TerminalParser { body, tokens: &tokens, pos: 0 };
    let info = parser.parse_sequence(None)?;
    let routes = info.terminal_route_sets.iter().flatten().cloned().collect();
    Ok(RouteAnalysis { routes, terminal_route_sets: info.terminal_route_sets })
}

struct TerminalParser<'a> {
    body: &'a str,
    tokens: &'a [Token],
    pos: usize,
}

#[derive(Debug, Clone, Copy)]
struct TerminalInfo {
    contains_become: bool,
    all_paths_terminal: bool,
}

impl TerminalInfo {
    fn empty() -> Self {
        Self { contains_become: false, all_paths_terminal: false }
    }

    fn terminal(routes: Vec<RouteCall>) -> TerminalResult {
        TerminalResult { info: Self { contains_become: true, all_paths_terminal: true }, terminal_route_sets: vec![routes] }
    }
}

#[derive(Debug, Clone)]
struct TerminalResult {
    info: TerminalInfo,
    terminal_route_sets: Vec<Vec<RouteCall>>,
}

impl TerminalResult {
    fn empty() -> Self {
        Self { info: TerminalInfo::empty(), terminal_route_sets: Vec::new() }
    }
}

impl TerminalParser<'_> {
    fn parse_sequence(&mut self, end: Option<char>) -> Result<TerminalResult> {
        let mut result = TerminalResult::empty();
        while !self.is_eof() && !end.is_some_and(|symbol| self.check_symbol(symbol)) {
            let stmt = self.parse_statement()?;
            result.info.contains_become |= stmt.info.contains_become;
            result.terminal_route_sets.extend(stmt.terminal_route_sets);

            if stmt.info.all_paths_terminal {
                while self.consume_symbol(';') {}
                if self.is_eof() || end.is_some_and(|symbol| self.check_symbol(symbol)) {
                    result.info.all_paths_terminal = true;
                    break;
                }
                return Err(self.error("`become` must be terminal; move following code into an explicit `else` branch"));
            }
            if stmt.info.contains_become {
                return Err(self.error("conditional `become` must be terminal on every branch; add an explicit `else` branch"));
            }
        }
        Ok(result)
    }

    fn parse_statement(&mut self) -> Result<TerminalResult> {
        if self.consume_ident(word::IF) {
            self.expect_symbol('(')?;
            self.skip_balanced('(', ')')?;
            let then_info = self.parse_block_or_statement()?;
            let else_info = if self.consume_ident(word::ELSE) { self.parse_block_or_statement()? } else { TerminalResult::empty() };
            let contains_become = then_info.info.contains_become || else_info.info.contains_become;
            let all_paths_terminal = then_info.info.all_paths_terminal && else_info.info.all_paths_terminal;
            let mut terminal_route_sets = then_info.terminal_route_sets;
            terminal_route_sets.extend(else_info.terminal_route_sets);

            Ok(TerminalResult { info: TerminalInfo { contains_become, all_paths_terminal }, terminal_route_sets })
        } else if self.consume_ident(word::BECOME) {
            let routes = self.parse_become_tail()?;
            Ok(TerminalInfo::terminal(routes))
        } else if self.consume_symbol('{') {
            let result = self.parse_sequence(Some('}'))?;
            self.expect_symbol('}')?;
            Ok(result)
        } else {
            self.skip_statement()?;
            Ok(TerminalResult::empty())
        }
    }

    fn parse_block_or_statement(&mut self) -> Result<TerminalResult> {
        if self.consume_symbol('{') {
            let result = self.parse_sequence(Some('}'))?;
            self.expect_symbol('}')?;
            Ok(result)
        } else {
            self.parse_statement()
        }
    }

    fn parse_become_tail(&mut self) -> Result<Vec<RouteCall>> {
        if self.consume_symbol('{') {
            let mut routes = Vec::new();
            while !self.check_symbol('}') && !self.is_eof() {
                if self.check_ident(word::BECOME) {
                    return Err(self.error("nested `become` blocks are not supported yet"));
                }
                routes.push(self.parse_route()?);
                self.consume_symbol(';');
            }
            self.expect_symbol('}')?;
            self.consume_symbol(';');
            return Ok(routes);
        }

        let route = self.parse_route()?;
        self.consume_symbol(';');
        Ok(vec![route])
    }

    fn parse_route(&mut self) -> Result<RouteCall> {
        let first = self.expect_any_ident()?;
        let (output, actor) = if self.consume_left_arrow() { (Some(first), self.expect_any_ident()?) } else { (None, first) };

        self.expect_symbol('(')?;
        let start = self.current().span.start;
        let mut depth = 1usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol('(') => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol(')') => {
                    depth -= 1;
                    if depth == 0 {
                        let state = self.body[start..token.span.start].trim().to_string();
                        self.advance();
                        return Ok(RouteCall { output, actor, state });
                    }
                    self.advance();
                }
                _ => self.advance(),
            }
        }

        Err(self.error("unterminated route state expression"))
    }

    fn consume_left_arrow(&mut self) -> bool {
        match self.current().kind {
            TokenKind::LeftArrow => {
                self.advance();
                true
            }
            TokenKind::Symbol('<') if matches!(self.peek_kind(1), Some(TokenKind::Symbol('-'))) => {
                self.advance();
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn expect_any_ident(&mut self) -> Result<String> {
        match self.current().kind.clone() {
            TokenKind::Ident(name) => {
                self.advance();
                Ok(name)
            }
            _ => Err(self.error("expected identifier in `become` route")),
        }
    }

    fn skip_statement(&mut self) -> Result<()> {
        self.skip_until_statement_end()
    }

    fn skip_until_statement_end(&mut self) -> Result<()> {
        while !self.is_eof() {
            match self.current().kind {
                TokenKind::Symbol(';') => {
                    self.advance();
                    return Ok(());
                }
                TokenKind::Symbol('{') => {
                    self.advance();
                    self.skip_balanced_after_open('{', '}')?;
                }
                TokenKind::Symbol('(') => {
                    self.advance();
                    self.skip_balanced_after_open('(', ')')?;
                }
                TokenKind::Symbol('[') => {
                    self.advance();
                    self.skip_balanced_after_open('[', ']')?;
                }
                TokenKind::Symbol('}') => return Ok(()),
                _ => self.advance(),
            }
        }
        Ok(())
    }

    fn skip_balanced(&mut self, open: char, close: char) -> Result<()> {
        self.skip_balanced_after_open(open, close)
    }

    fn skip_balanced_after_open(&mut self, open: char, close: char) -> Result<()> {
        let mut depth = 1usize;
        while !self.is_eof() {
            match self.current().kind {
                TokenKind::Symbol(symbol) if symbol == open => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol(symbol) if symbol == close => {
                    depth -= 1;
                    self.advance();
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.advance(),
            }
        }
        Err(self.error(format!("unterminated `{open}` group")))
    }

    fn expect_symbol(&mut self, expected: char) -> Result<()> {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}`"))),
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

    fn check_ident(&self, expected: &str) -> bool {
        matches!(&self.current().kind, TokenKind::Ident(actual) if actual == expected)
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

    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_kind(&self, offset: usize) -> Option<&TokenKind> {
        self.tokens.get(self.pos + offset).map(|token| &token.kind)
    }

    fn advance(&mut self) {
        if !self.is_eof() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        matches!(self.current().kind, TokenKind::Eof)
    }

    fn error(&self, message: impl Into<String>) -> ArgentError {
        let snippet = self.body.get(self.current().span.start..).unwrap_or("");
        let preview = snippet.lines().next().unwrap_or("").trim().chars().take(80).collect::<String>();
        ArgentError::new(format!("{} at body byte {} near `{}`", message.into(), self.current().span.start, preview))
    }
}

#[cfg(test)]
mod tests {
    use super::collect_routes;

    #[test]
    fn extracts_atomic_named_routes() {
        let routes = collect_routes(
            r#"
            become {
                player_a_out <- Player(next_player_a);
                player_b_out <- Player(next_player_b);
            };
            "#,
        )
        .expect("routes parse");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].output.as_deref(), Some("player_a_out"));
        assert_eq!(routes[0].actor, "Player");
        assert_eq!(routes[0].state, "next_player_a");
        assert_eq!(routes[1].output.as_deref(), Some("player_b_out"));
        assert_eq!(routes[1].actor, "Player");
        assert_eq!(routes[1].state, "next_player_b");
    }

    #[test]
    fn extracts_implicit_single_output_route() {
        let routes = collect_routes(
            r#"
            become Done({
                final_value: next_value,
            });
            "#,
        )
        .expect("routes parse");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].output, None);
        assert_eq!(routes[0].actor, "Done");
        assert!(routes[0].state.contains("final_value"));
    }

    #[test]
    fn rejects_become_with_parent_fallthrough() {
        let err = collect_routes(
            r#"
            if (done) {
                become next <- Done(ticket);
            }
            become next <- Live(state);
            "#,
        )
        .expect_err("fallthrough after conditional become must be rejected");

        assert!(err.to_string().contains("must be terminal"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_one_sided_conditional_become() {
        let err = collect_routes(
            r#"
            if (done) {
                become next <- Done(ticket);
            }
            "#,
        )
        .expect_err("one-sided conditional become must be rejected");

        assert!(err.to_string().contains("explicit `else`"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_terminal_if_else_becomes() {
        let routes = collect_routes(
            r#"
            if (done) {
                become next <- Done(ticket);
            } else {
                become next <- Live(state);
            }
            "#,
        )
        .expect("terminal if/else becomes parse");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].actor, "Done");
        assert_eq!(routes[1].actor, "Live");
    }
}
