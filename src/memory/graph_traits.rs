use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            anyhow::bail!("node id cannot be empty");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionRuleId(String);

impl DecisionRuleId {
    pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            anyhow::bail!("decision rule id cannot be empty");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    CategoryMembership,
    DecisionConstraint,
    MessageLink,
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    Outbound,
    Inbound,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynapseNodeType {
    MemoryCore,
    MemoryDaily,
    MemoryConversation,
    MemoryCustom,
    DecisionRule,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNodeUpsert {
    pub id: NodeId,
    pub node_type: SynapseNodeType,
    pub content: String,
    pub agent_role: Option<AgentRole>,
    pub decision_rule_id: Option<DecisionRuleId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdgeUpsert {
    pub source: NodeId,
    pub target: NodeId,
    pub relation: RelationType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborhoodQuery {
    pub anchor: NodeId,
    pub direction: EdgeDirection,
    pub relation: Option<RelationType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSymbolicFilter {
    pub relation: Option<RelationType>,
    pub node_type: Option<SynapseNodeType>,
    pub agent_role: Option<AgentRole>,
    pub decision_rule_id: Option<DecisionRuleId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticGraphQuery {
    pub text: String,
    pub limit: usize,
    pub filter: Option<SemanticSymbolicFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: NodeId,
    pub node_type: SynapseNodeType,
    pub content: String,
    pub agent_role: Option<AgentRole>,
    pub decision_rule_id: Option<DecisionRuleId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: NodeId,
    pub target: NodeId,
    pub relation: RelationType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphSearchResult {
    pub node: GraphNode,
    pub score: f32,
}

#[async_trait]
pub trait GraphMemory: Send + Sync {
    async fn upsert_node(&self, node: GraphNodeUpsert) -> anyhow::Result<()>;

    async fn upsert_typed_edge(&self, edge: GraphEdgeUpsert) -> anyhow::Result<()>;

    async fn query_by_neighborhood(
        &self,
        query: NeighborhoodQuery,
    ) -> anyhow::Result<Vec<GraphEdge>>;

    async fn semantic_search_with_filters(
        &self,
        query: SemanticGraphQuery,
    ) -> anyhow::Result<Vec<GraphSearchResult>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_rejects_empty_values() {
        let result = NodeId::new("  ");
        assert!(result.is_err());
    }

    #[test]
    fn decision_rule_id_rejects_empty_values() {
        let result = DecisionRuleId::new(" ");
        assert!(result.is_err());
    }

    #[test]
    fn relation_type_custom_roundtrip() {
        let relation = RelationType::Custom("references".into());
        let json = serde_json::to_string(&relation).unwrap();
        let parsed: RelationType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, relation);
    }
}
