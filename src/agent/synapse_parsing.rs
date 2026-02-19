use anyhow::Result;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryOpType {
    Upsert,
    Delete,
    Query,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryFact {
    pub subject: String,
    pub predicate: String,
    pub object: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryOp {
    pub op_type: MemoryOpType,
    pub facts: Vec<MemoryFact>,
    pub query: Option<String>,
}

// Regex for the main block: <memory_op type="..."> content </memory_op>
static MEMORY_OP_BLOCK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<memory_op(?:\s+type="([^"]+)")?>(.*?)</memory_op>"#).unwrap()
});

// Regex for individual facts: <fact s="..." p="..." o="..." />
static MEMORY_FACT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<fact\s+s="([^"]+)"\s+p="([^"]+)"\s+o="([^"]+)"\s*/?>"#).unwrap()
});

pub fn parse_memory_ops(text: &str) -> Vec<MemoryOp> {
    let mut ops = Vec::new();

    for caps in MEMORY_OP_BLOCK_REGEX.captures_iter(text) {
        let op_type_str = caps.get(1).map_or("upsert", |m| m.as_str());
        let content = caps.get(2).map_or("", |m| m.as_str());

        let op_type = match op_type_str.to_lowercase().as_str() {
            "delete" => MemoryOpType::Delete,
            "query" => MemoryOpType::Query,
            _ => MemoryOpType::Upsert,
        };

        if op_type == MemoryOpType::Query {
            // content is the raw query (e.g. SPARQL)
            ops.push(MemoryOp {
                op_type,
                facts: Vec::new(),
                query: Some(content.trim().to_string()),
            });
        } else {
            // Parse facts
            let mut facts = Vec::new();
            for fact_caps in MEMORY_FACT_REGEX.captures_iter(content) {
                if let (Some(s), Some(p), Some(o)) = (fact_caps.get(1), fact_caps.get(2), fact_caps.get(3)) {
                    facts.push(MemoryFact {
                        subject: s.as_str().to_string(),
                        predicate: p.as_str().to_string(),
                        object: o.as_str().to_string(),
                    });
                }
            }
            if !facts.is_empty() {
                ops.push(MemoryOp {
                    op_type,
                    facts,
                    query: None,
                });
            }
        }
    }

    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_upsert() {
        let input = r#"
        Thinking about the user...
        <memory_op type="upsert">
            <fact s="User" p="prefers" o="Concise" />
            <fact s="Project" p="status" o="Active" />
        </memory_op>
        Done.
        "#;
        let ops = parse_memory_ops(input);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op_type, MemoryOpType::Upsert);
        assert_eq!(ops[0].facts.len(), 2);
        assert_eq!(ops[0].facts[0].subject, "User");
        assert_eq!(ops[0].facts[0].object, "Concise");
    }

    #[test]
    fn test_parse_delete_and_query() {
        let input = r#"
        <memory_op type="delete">
            <fact s="Old" p="status" o="Active" />
        </memory_op>
        <memory_op type="query">
            SELECT ?s WHERE { ?s ?p ?o }
        </memory_op>
        "#;
        let ops = parse_memory_ops(input);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op_type, MemoryOpType::Delete);
        assert_eq!(ops[1].op_type, MemoryOpType::Query);
        assert_eq!(ops[1].query.as_deref(), Some("SELECT ?s WHERE { ?s ?p ?o }"));
    }

    #[test]
    fn test_malformed_xml_graceful() {
        let input = r#"<memory_op type="upsert"> <fact s="OnlySubject" /> </memory_op>"#;
        let ops = parse_memory_ops(input);
        assert_eq!(ops.len(), 0); // Should skip incomplete fact
    }
}
