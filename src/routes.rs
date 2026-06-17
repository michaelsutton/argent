use crate::ast::RouteCall;
use crate::error::{ArgentError, Result};
use crate::lexer::{Token, TokenKind, lex};

pub fn collect_routes(body: &str) -> Result<Vec<RouteCall>> {
    let tokens = lex(body)?;
    validate_terminal_becomes(body, &tokens)?;
    let mut parser = RouteParser { body, tokens, pos: 0, routes: Vec::new() };
    parser.parse()?;
    Ok(parser.routes)
}

fn validate_terminal_becomes(body: &str, tokens: &[Token]) -> Result<()> {
    let mut parser = TerminalParser { body, tokens, pos: 0 };
    parser.parse_sequence(None)?;
    Ok(())
}

struct RouteParser<'a> {
    body: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    routes: Vec<RouteCall>,
}

impl RouteParser<'_> {
    fn parse(&mut self) -> Result<()> {
        while !self.is_eof() {
            if self.consume_ident("become") {
                self.parse_become()?;
            } else {
                self.advance();
            }
        }
        Ok(())
    }

    fn parse_become(&mut self) -> Result<()> {
        if self.consume_symbol('{') {
            while !self.check_symbol('}') && !self.is_eof() {
                if self.check_ident("become") {
                    return Err(self.error("nested `become` blocks are not supported yet"));
                }
                let route = self.parse_route()?;
                self.routes.push(route);
                self.consume_symbol(';');
            }
            self.expect_symbol('}')?;
            self.consume_symbol(';');
        } else {
            let route = self.parse_route()?;
            self.routes.push(route);
            self.consume_symbol(';');
        }
        Ok(())
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

    fn expect_symbol(&mut self, expected: char) -> Result<()> {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}` in `become` route"))),
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
        ArgentError::new(format!("{} at body byte {}", message.into(), self.current().span.start))
    }
}

struct TerminalParser<'a> {
    body: &'a str,
    tokens: &'a [Token],
    pos: usize,
}

#[derive(Debug, Clone, Copy)]
struct TerminalInfo {
    contains_become: bool,
}

impl TerminalInfo {
    fn empty() -> Self {
        Self { contains_become: false }
    }
}

impl TerminalParser<'_> {
    fn parse_sequence(&mut self, end: Option<char>) -> Result<TerminalInfo> {
        let mut info = TerminalInfo::empty();
        while !self.is_eof() && !end.is_some_and(|symbol| self.check_symbol(symbol)) {
            let stmt = self.parse_statement()?;
            info.contains_become |= stmt.contains_become;
            if stmt.contains_become {
                while self.consume_symbol(';') {}
                if self.is_eof() || end.is_some_and(|symbol| self.check_symbol(symbol)) {
                    break;
                }
                return Err(self.error("`become` must be terminal; move following code into an explicit `else` branch"));
            }
        }
        Ok(info)
    }

    fn parse_statement(&mut self) -> Result<TerminalInfo> {
        if self.consume_ident("if") {
            self.expect_symbol('(')?;
            self.skip_balanced('(', ')')?;
            let then_info = self.parse_block_or_statement()?;
            let else_info = if self.consume_ident("else") { self.parse_block_or_statement()? } else { TerminalInfo::empty() };
            Ok(TerminalInfo { contains_become: then_info.contains_become || else_info.contains_become })
        } else if self.consume_ident("become") {
            self.skip_become_tail()?;
            Ok(TerminalInfo { contains_become: true })
        } else if self.consume_symbol('{') {
            let info = self.parse_sequence(Some('}'))?;
            self.expect_symbol('}')?;
            Ok(info)
        } else {
            self.skip_statement()?;
            Ok(TerminalInfo::empty())
        }
    }

    fn parse_block_or_statement(&mut self) -> Result<TerminalInfo> {
        if self.consume_symbol('{') {
            let info = self.parse_sequence(Some('}'))?;
            self.expect_symbol('}')?;
            Ok(info)
        } else {
            self.parse_statement()
        }
    }

    fn skip_become_tail(&mut self) -> Result<()> {
        if self.consume_symbol('{') {
            self.skip_balanced_after_open('{', '}')?;
            self.consume_symbol(';');
            return Ok(());
        }

        self.skip_until_statement_end()
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
