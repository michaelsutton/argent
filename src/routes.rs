use crate::ast::RouteCall;
use crate::error::{ArgentError, Result};
use crate::lexer::{lex, Token, TokenKind};

pub fn collect_routes(body: &str) -> Result<Vec<RouteCall>> {
    let tokens = lex(body)?;
    let mut parser = RouteParser {
        body,
        tokens,
        pos: 0,
        routes: Vec::new(),
    };
    parser.parse()?;
    Ok(parser.routes)
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
        let (output, actor) = if self.consume_left_arrow() {
            (Some(first), self.expect_any_ident()?)
        } else {
            (None, first)
        };

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
                        return Ok(RouteCall {
                            output,
                            actor,
                            state,
                        });
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
        ArgentError::new(format!(
            "{} at body byte {}",
            message.into(),
            self.current().span.start
        ))
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
}
