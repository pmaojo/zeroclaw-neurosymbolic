use super::graph_traits::{
    EdgeDirection, GraphEdge, GraphEdgeUpsert, GraphMemory, GraphNode, GraphNodeUpsert,
    GraphSearchResult, NeighborhoodQuery, NodeId, SemanticGraphQuery,
};
use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::RwLock;

pub struct SynapseMemory {
    local: SqliteMemory,
    graph_nodes: RwLock<HashMap<NodeId, GraphNode>>,
    graph_edges: RwLock<Vec<GraphEdge>>,
}

impl SynapseMemory {
    pub fn new(workspace_dir: &Path, local: SqliteMemory) -> anyhow::Result<Self> {
        Self::initialize(workspace_dir)?;
        Ok(Self {
            local,
            graph_nodes: RwLock::new(HashMap::new()),
            graph_edges: RwLock::new(Vec::new()),
        })
    }

    fn initialize(workspace_dir: &Path) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let _synapse_marker = std::any::TypeId::of::<synapse_engine::Engine>();
            let _workspace_dir = workspace_dir;
            if std::env::var_os("ZEROCLAW_FORCE_SYNAPSE_INIT_ERROR").is_some() {
                anyhow::bail!("forced synapse initialization error");
            }
            return Ok(());
        }

        #[cfg(not(feature = "memory-synapse"))]
        {
            let _workspace_dir = workspace_dir;
            anyhow::bail!(
                "memory backend 'synapse' requires feature 'memory-synapse'; using sqlite fallback"
            );
        }
    }
}

#[async_trait]
impl Memory for SynapseMemory {
    fn name(&self) -> &str {
        "synapse"
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.local.store(key, content, category, session_id).await
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.local.recall(query, limit, session_id).await
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<MemoryEntry>> {
        self.local.get(key).await
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.local.list(category, session_id).await
    }

    async fn forget(&self, key: &str) -> anyhow::Result<bool> {
        self.local.forget(key).await
    }

    async fn count(&self) -> anyhow::Result<usize> {
        self.local.count().await
    }

    async fn health_check(&self) -> bool {
        self.local.health_check().await
    }
}

#[async_trait]
impl GraphMemory for SynapseMemory {
    async fn upsert_node(&self, node: GraphNodeUpsert) -> anyhow::Result<()> {
        let graph_node = GraphNode {
            id: node.id.clone(),
            node_type: node.node_type,
            content: node.content,
            agent_role: node.agent_role,
            decision_rule_id: node.decision_rule_id,
        };

        let mut nodes = self.graph_nodes.write().await;
        nodes.insert(node.id, graph_node);
        Ok(())
    }

    async fn upsert_typed_edge(&self, edge: GraphEdgeUpsert) -> anyhow::Result<()> {
        let mut edges = self.graph_edges.write().await;
        if let Some(existing) = edges.iter_mut().find(|candidate| {
            candidate.source == edge.source
                && candidate.target == edge.target
                && candidate.relation == edge.relation
        }) {
            *existing = GraphEdge {
                source: edge.source,
                target: edge.target,
                relation: edge.relation,
            };
            return Ok(());
        }

        edges.push(GraphEdge {
            source: edge.source,
            target: edge.target,
            relation: edge.relation,
        });
        Ok(())
    }

    async fn query_by_neighborhood(
        &self,
        query: NeighborhoodQuery,
    ) -> anyhow::Result<Vec<GraphEdge>> {
        let edges = self.graph_edges.read().await;
        let matches = edges
            .iter()
            .filter(|edge| {
                let relation_matches = query
                    .relation
                    .as_ref()
                    .map(|relation| relation == &edge.relation)
                    .unwrap_or(true);

                if !relation_matches {
                    return false;
                }

                match query.direction {
                    EdgeDirection::Outbound => edge.source == query.anchor,
                    EdgeDirection::Inbound => edge.target == query.anchor,
                    EdgeDirection::Both => {
                        edge.source == query.anchor || edge.target == query.anchor
                    }
                }
            })
            .cloned()
            .collect();

        Ok(matches)
    }

    async fn semantic_search_with_filters(
        &self,
        query: SemanticGraphQuery,
    ) -> anyhow::Result<Vec<GraphSearchResult>> {
        let nodes = self.graph_nodes.read().await;
        let edges = self.graph_edges.read().await;
        let query_text = query.text.trim().to_lowercase();

        let mut matches = Vec::new();

        for node in nodes.values() {
            if let Some(filter) = &query.filter {
                if filter
                    .node_type
                    .as_ref()
                    .is_some_and(|node_type| node_type != &node.node_type)
                {
                    continue;
                }

                if filter
                    .agent_role
                    .as_ref()
                    .is_some_and(|agent_role| Some(*agent_role) != node.agent_role)
                {
                    continue;
                }

                if filter
                    .decision_rule_id
                    .as_ref()
                    .is_some_and(|rule_id| Some(rule_id) != node.decision_rule_id.as_ref())
                {
                    continue;
                }

                if let Some(relation) = filter.relation.as_ref() {
                    let relation_exists = edges.iter().any(|edge| {
                        (edge.source == node.id || edge.target == node.id)
                            && &edge.relation == relation
                    });
                    if !relation_exists {
                        continue;
                    }
                }
            }

            let content_lower = node.content.to_lowercase();
            if !query_text.is_empty() && !content_lower.contains(&query_text) {
                continue;
            }

            let score = if query_text.is_empty() {
                1.0
            } else if content_lower == query_text {
                1.0
            } else {
                0.8
            };

            matches.push(GraphSearchResult {
                node: node.clone(),
                score,
            });
        }

        matches.sort_by(|a, b| b.score.total_cmp(&a.score));
        matches.truncate(query.limit);
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "memory-synapse")]
    use crate::memory::graph_traits::{
        AgentRole, DecisionRuleId, RelationType, SemanticSymbolicFilter, SynapseNodeType,
    };
    use tempfile::TempDir;

    #[test]
    #[cfg(feature = "memory-synapse")]
    fn synapse_memory_initializes_when_feature_enabled() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let memory = SynapseMemory::new(tmp.path(), sqlite).unwrap();
        assert_eq!(memory.name(), "synapse");
    }

    #[test]
    #[cfg(not(feature = "memory-synapse"))]
    fn synapse_memory_requires_feature_flag() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let result = SynapseMemory::new(tmp.path(), sqlite);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error
            .to_string()
            .contains("requires feature 'memory-synapse'"));
    }

    #[tokio::test]
    #[cfg(feature = "memory-synapse")]
    async fn graph_memory_upsert_and_query_neighborhood() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let memory = SynapseMemory::new(tmp.path(), sqlite).unwrap();

        let source = NodeId::new("node-a").unwrap();
        let target = NodeId::new("node-b").unwrap();

        memory
            .upsert_node(GraphNodeUpsert {
                id: source.clone(),
                node_type: SynapseNodeType::Agent,
                content: "ZeroClaw assistant node".into(),
                agent_role: Some(AgentRole::Assistant),
                decision_rule_id: None,
            })
            .await
            .unwrap();

        memory
            .upsert_node(GraphNodeUpsert {
                id: target.clone(),
                node_type: SynapseNodeType::DecisionRule,
                content: "apply deterministic policy".into(),
                agent_role: None,
                decision_rule_id: Some(DecisionRuleId::new("rule-1").unwrap()),
            })
            .await
            .unwrap();

        memory
            .upsert_typed_edge(GraphEdgeUpsert {
                source: source.clone(),
                target: target.clone(),
                relation: RelationType::DecisionConstraint,
            })
            .await
            .unwrap();

        let outbound = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: source,
                direction: EdgeDirection::Outbound,
                relation: Some(RelationType::DecisionConstraint),
            })
            .await
            .unwrap();

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].target, target);
    }

    #[tokio::test]
    #[cfg(feature = "memory-synapse")]
    async fn graph_memory_semantic_search_applies_symbolic_filters() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let memory = SynapseMemory::new(tmp.path(), sqlite).unwrap();

        let node = NodeId::new("conversation-node").unwrap();
        let rule_id = DecisionRuleId::new("rule-priority").unwrap();

        memory
            .upsert_node(GraphNodeUpsert {
                id: node.clone(),
                node_type: SynapseNodeType::MemoryConversation,
                content: "user asked for semantic graph search".into(),
                agent_role: Some(AgentRole::User),
                decision_rule_id: Some(rule_id.clone()),
            })
            .await
            .unwrap();

        memory
            .upsert_typed_edge(GraphEdgeUpsert {
                source: node.clone(),
                target: NodeId::new("rule-node").unwrap(),
                relation: RelationType::DecisionConstraint,
            })
            .await
            .unwrap();

        let results = memory
            .semantic_search_with_filters(SemanticGraphQuery {
                text: "semantic graph".into(),
                limit: 10,
                filter: Some(SemanticSymbolicFilter {
                    relation: Some(RelationType::DecisionConstraint),
                    node_type: Some(SynapseNodeType::MemoryConversation),
                    agent_role: Some(AgentRole::User),
                    decision_rule_id: Some(rule_id),
                }),
            })
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].node.id, node);
        assert!(results[0].score > 0.0);
    }
}
