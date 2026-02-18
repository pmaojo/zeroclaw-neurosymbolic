use crate::memory::graph_traits::{
    GraphEdge, GraphEdgeUpsert, GraphNode, GraphNodeUpsert, GraphSearchResult, NeighborhoodQuery,
    NodeId, RelationType, SynapseNodeType,
};
use crate::memory::synapse::ontology::{classes, namespaces, properties};
use crate::memory::synapse_domain_adapter::SynapseDomainAdapter;
use crate::memory::traits::MemoryCategory;
use serde_json::Value;

pub type SynapseTriple = (String, String, String);

pub trait SynapseGraphAdapterPort: Send + Sync {
    fn memory_store_triples(
        &self,
        key: &str,
        content: &str,
        category: &MemoryCategory,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<SynapseTriple>>;

    fn node_upsert_triples(&self, node: GraphNodeUpsert) -> anyhow::Result<Vec<SynapseTriple>>;

    fn edge_upsert_triple(&self, edge: GraphEdgeUpsert) -> anyhow::Result<SynapseTriple>;

    fn neighborhood_query(&self, query: &NeighborhoodQuery) -> String;

    fn hydrate_edges(&self, raw: &str) -> anyhow::Result<Vec<GraphEdge>>;

    fn hydrate_search_result(&self, uri: &str, score: f32) -> anyhow::Result<GraphSearchResult>;
}

#[derive(Default)]
pub struct SynapseGraphAdapter;

impl SynapseGraphAdapter {
    fn relation_to_predicate(&self, relation: &RelationType) -> String {
        match relation {
            RelationType::CategoryMembership => namespaces::RDF.to_owned() + "type",
            RelationType::DecisionConstraint => properties::RELATES_TO.to_string(),
            RelationType::MessageLink => properties::CONTEXT_FOR.to_string(),
            RelationType::Custom(value) => format!("{}{}", namespaces::ZEROCLAW, value),
        }
    }

    fn predicate_to_relation(&self, predicate: &str) -> anyhow::Result<RelationType> {
        if predicate == (namespaces::RDF.to_owned() + "type") {
            return Ok(RelationType::CategoryMembership);
        }
        if predicate == properties::RELATES_TO {
            return Ok(RelationType::DecisionConstraint);
        }
        if predicate == properties::CONTEXT_FOR {
            return Ok(RelationType::MessageLink);
        }

        if let Some(custom) = predicate.strip_prefix(namespaces::ZEROCLAW) {
            if custom.trim().is_empty() {
                anyhow::bail!("custom relation predicate suffix cannot be empty");
            }
            return Ok(RelationType::Custom(custom.to_string()));
        }

        anyhow::bail!("unsupported predicate for relation mapping: {predicate}")
    }

    fn node_type_to_rdf_class(&self, node_type: &SynapseNodeType) -> &'static str {
        match node_type {
            SynapseNodeType::Agent => classes::AGENT,
            SynapseNodeType::DecisionRule => classes::DECISION_RULE,
            SynapseNodeType::MemoryConversation => classes::CONVERSATION,
            _ => classes::MEMORY,
        }
    }

    fn node_id_from_uri(&self, uri: &str) -> anyhow::Result<NodeId> {
        let normalized = uri.trim().trim_start_matches('<').trim_end_matches('>');
        let raw_id = normalized
            .strip_prefix(namespaces::ZEROCLAW)
            .ok_or_else(|| {
                anyhow::anyhow!("expected node URI in zeroclaw namespace, got: {uri}")
            })?;
        NodeId::new(raw_id)
    }

    fn parse_graph_edge_binding(&self, row: &Value) -> anyhow::Result<GraphEdge> {
        let source_uri = row
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'source' binding in SPARQL row: {row}"))?;
        let predicate_uri = row
            .get("predicate")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'predicate' binding in SPARQL row: {row}"))?;
        let target_uri = row
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'target' binding in SPARQL row: {row}"))?;

        Ok(GraphEdge {
            source: self.node_id_from_uri(source_uri)?,
            target: self.node_id_from_uri(target_uri)?,
            relation: self.predicate_to_relation(predicate_uri.trim_matches(['<', '>']))?,
        })
    }

    fn escaped_literal(&self, text: &str) -> String {
        format!("\"{}\"", text.replace('"', "\\\""))
    }
}

impl SynapseGraphAdapterPort for SynapseGraphAdapter {
    fn memory_store_triples(
        &self,
        key: &str,
        content: &str,
        category: &MemoryCategory,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<SynapseTriple>> {
        let node_uri = format!("{}Memory/{key}", namespaces::ZEROCLAW);
        let node_type = SynapseDomainAdapter::category_to_node_type(category);
        let category_relation = SynapseDomainAdapter::category_to_relation_type(category);

        let mut triples = vec![
            (
                node_uri.clone(),
                namespaces::RDF.to_owned() + "type",
                self.node_type_to_rdf_class(&node_type).to_string(),
            ),
            (
                node_uri.clone(),
                properties::HAS_CONTENT.to_string(),
                self.escaped_literal(content),
            ),
        ];

        if let Some(sess) = session_id {
            triples.push((
                node_uri,
                self.relation_to_predicate(&category_relation),
                format!("{}Session/{sess}", namespaces::ZEROCLAW),
            ));
        }

        Ok(triples)
    }

    fn node_upsert_triples(&self, node: GraphNodeUpsert) -> anyhow::Result<Vec<SynapseTriple>> {
        let node_uri = format!("{}{}", namespaces::ZEROCLAW, node.id.as_str());

        let mut triples = vec![
            (
                node_uri.clone(),
                namespaces::RDF.to_owned() + "type",
                self.node_type_to_rdf_class(&node.node_type).to_string(),
            ),
            (
                node_uri.clone(),
                properties::HAS_CONTENT.to_string(),
                self.escaped_literal(&node.content),
            ),
        ];

        if let Some(role) = node.agent_role {
            triples.push((
                node_uri,
                properties::HAS_ROLE.to_string(),
                self.escaped_literal(&format!("{:?}", role)),
            ));
        }

        Ok(triples)
    }

    fn edge_upsert_triple(&self, edge: GraphEdgeUpsert) -> anyhow::Result<SynapseTriple> {
        Ok((
            format!("{}{}", namespaces::ZEROCLAW, edge.source.as_str()),
            self.relation_to_predicate(&edge.relation),
            format!("{}{}", namespaces::ZEROCLAW, edge.target.as_str()),
        ))
    }

    fn neighborhood_query(&self, query: &NeighborhoodQuery) -> String {
        let anchor_uri = format!("<{}{}>", namespaces::ZEROCLAW, query.anchor.as_str());
        let relation_filter = query
            .relation
            .as_ref()
            .map(|relation| self.relation_to_predicate(relation))
            .map(|predicate| format!("VALUES ?predicate {{ <{}> }}", predicate))
            .unwrap_or_default();

        let where_clause = match query.direction {
            crate::memory::graph_traits::EdgeDirection::Outbound => {
                format!(
                    "BIND({anchor} AS ?source)\n?source ?predicate ?target .\nFILTER(isIRI(?target))",
                    anchor = anchor_uri
                )
            }
            crate::memory::graph_traits::EdgeDirection::Inbound => {
                format!(
                    "BIND({anchor} AS ?target)\n?source ?predicate ?target .\nFILTER(isIRI(?source))",
                    anchor = anchor_uri
                )
            }
            crate::memory::graph_traits::EdgeDirection::Both => {
                format!(
                    "{{\n  BIND({anchor} AS ?source)\n  ?source ?predicate ?target .\n  FILTER(isIRI(?target))\n}} UNION {{\n  BIND({anchor} AS ?target)\n  ?source ?predicate ?target .\n  FILTER(isIRI(?source))\n}}",
                    anchor = anchor_uri
                )
            }
        };

        if relation_filter.is_empty() {
            format!(
                "SELECT ?source ?predicate ?target WHERE {{\n{where_clause}\n}} ORDER BY ?source ?predicate ?target",
            )
        } else {
            format!(
                "SELECT ?source ?predicate ?target WHERE {{\n{where_clause}\n{relation_filter}\n}} ORDER BY ?source ?predicate ?target",
            )
        }
    }

    fn hydrate_edges(&self, raw: &str) -> anyhow::Result<Vec<GraphEdge>> {
        let rows: Vec<Value> = serde_json::from_str(raw)?;
        let mut edges = Vec::with_capacity(rows.len());
        for row in rows {
            edges.push(self.parse_graph_edge_binding(&row)?);
        }
        Ok(edges)
    }

    fn hydrate_search_result(&self, uri: &str, score: f32) -> anyhow::Result<GraphSearchResult> {
        let id_str = uri.replace(namespaces::ZEROCLAW, "");
        let id = NodeId::new(id_str)?;

        Ok(GraphSearchResult {
            node: GraphNode {
                id,
                node_type: SynapseNodeType::MemoryCore,
                content: "loaded from synapse".into(),
                agent_role: None,
                decision_rule_id: None,
            },
            score,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::graph_traits::{AgentRole, EdgeDirection, NeighborhoodQuery};

    #[test]
    fn memory_store_triples_map_category_and_session() {
        let adapter = SynapseGraphAdapter;
        let triples = adapter
            .memory_store_triples(
                "k1",
                "hello",
                &MemoryCategory::Conversation,
                Some("session-a"),
            )
            .expect("triples build");

        assert_eq!(triples.len(), 3);
        assert_eq!(triples[0].1, namespaces::RDF.to_owned() + "type");
        assert_eq!(triples[0].2, classes::CONVERSATION);
        assert_eq!(triples[2].1, properties::CONTEXT_FOR);
        assert_eq!(
            triples[2].2,
            format!("{}Session/session-a", namespaces::ZEROCLAW)
        );
    }

    #[test]
    fn edge_hydration_maps_predicate_to_relation() {
        let adapter = SynapseGraphAdapter;
        let raw = format!(
            r#"[
            {{"source":"{ns}node-a","predicate":"{pred}","target":"{ns}node-b"}}
        ]"#,
            ns = namespaces::ZEROCLAW,
            pred = properties::RELATES_TO
        );

        let edges = adapter.hydrate_edges(&raw).expect("edge hydration");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source.as_str(), "node-a");
        assert_eq!(edges[0].target.as_str(), "node-b");
        assert_eq!(edges[0].relation, RelationType::DecisionConstraint);
    }

    #[test]
    fn node_upsert_triples_include_role_when_available() {
        let adapter = SynapseGraphAdapter;
        let triples = adapter
            .node_upsert_triples(GraphNodeUpsert {
                id: NodeId::new("agent-1").expect("id"),
                node_type: SynapseNodeType::Agent,
                content: "content".into(),
                agent_role: Some(AgentRole::Assistant),
                decision_rule_id: None,
            })
            .expect("node triples");

        assert_eq!(triples.len(), 3);
        assert_eq!(triples[0].2, classes::AGENT);
        assert_eq!(triples[2].1, properties::HAS_ROLE);
    }

    #[test]
    fn neighborhood_query_with_relation_filter_is_deterministic() {
        let adapter = SynapseGraphAdapter;
        let query = NeighborhoodQuery {
            anchor: NodeId::new("anchor").expect("id"),
            direction: EdgeDirection::Outbound,
            relation: Some(RelationType::MessageLink),
        };

        let sparql = adapter.neighborhood_query(&query);
        assert!(sparql.contains("ORDER BY ?source ?predicate ?target"));
        assert!(sparql.contains(properties::CONTEXT_FOR));
    }
}
