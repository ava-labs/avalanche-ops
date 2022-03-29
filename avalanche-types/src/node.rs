use std::io::{self, Error, ErrorKind};

/// Defines the node type.
/// MUST BE either "anchor" or "non-anchor"
#[derive(Eq, PartialEq, Clone)]
pub enum Kind {
    Anchor,
    NonAnchor,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Anchor => "anchor",
            Kind::NonAnchor => "non-anchor",
        }
    }
    pub fn from_str(&self, s: &str) -> io::Result<Self> {
        match s {
            "anchor" => Ok(Kind::Anchor),
            "non-anchor" => Ok(Kind::NonAnchor),
            "non_anchor" => Ok(Kind::NonAnchor),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("unknown node type '{}'", s),
            )),
        }
    }
}
