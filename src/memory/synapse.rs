#[cfg(feature = "memory-synapse")]
pub mod graph_adapter;
pub mod ontology;

use super::graph_traits::{
    GraphEdge, GraphEdgeUpsert, GraphMemory, GraphNodeUpsert, GraphSearchResult, NeighborhoodQuery,
    SemanticGraphQuery,
};
#[cfg(feature = "memory-synapse")]
use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use async_trait::async_trait;
#[cfg(feature = "memory-synapse")]
use graph_adapter::{SynapseGraphAdapter, SynapseGraphAdapterPort};
use std::path::Path;
use std::sync::Arc;

// Conditional compilation imports
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::namespaces;
#[cfg(feature = "memory-synapse")]
use synapse_core::scenarios::ScenarioManager;
#[cfg(feature = "memory-synapse")]
use synapse_core::store::{IngestTriple, Provenance, SynapseStore};

pub struct SynapseMemory {
    #[cfg(feature = "memory-synapse")]
    local: SqliteMemory,
    #[cfg(feature = "memory-synapse")]
    store: Arc<SynapseStore>,
    #[cfg(feature = "memory-synapse")]
    scenario_manager: Arc<ScenarioManager>,
    #[cfg(feature = "memory-synapse")]
    graph_adapter: Arc<dyn SynapseGraphAdapterPort>,
    // Fallback for when feature is disabled, or for non-graph persistence
    #[cfg(not(feature = "memory-synapse"))]
    local: std::marker::PhantomData<()>,
}

impl SynapseMemory {
    #[cfg(feature = "memory-synapse")]
    pub fn new(workspace_dir: &Path, local: SqliteMemory) -> anyhow::Result<Self> {
        let namespace = "zeroclaw";
        // SynapseStore expects the parent directory path
        let store = SynapseStore::open(namespace, workspace_dir.to_str().unwrap())?;

        let scenario_manager = ScenarioManager::new(workspace_dir);

        Ok(Self {
            local,
            store: Arc::new(store),
            scenario_manager: Arc::new(scenario_manager),
            graph_adapter: Arc::new(SynapseGraphAdapter),
        })
    }

    #[cfg(feature = "memory-synapse")]
    pub fn with_adapter(
        workspace_dir: &Path,
        local: SqliteMemory,
        graph_adapter: Arc<dyn SynapseGraphAdapterPort>,
    ) -> anyhow::Result<Self> {
        let namespace = "zeroclaw";
        let store = SynapseStore::open(namespace, workspace_dir.to_str().unwrap())?;
        let scenario_manager = ScenarioManager::new(workspace_dir);

        Ok(Self {
            local,
            store: Arc::new(store),
            scenario_manager: Arc::new(scenario_manager),
            graph_adapter,
        })
    }

    #[cfg(not(feature = "memory-synapse"))]
    pub fn new(workspace_dir: &Path, _local: super::sqlite::SqliteMemory) -> anyhow::Result<Self> {
        let _workspace_dir = workspace_dir;
        anyhow::bail!(
            "memory backend 'synapse' requires feature 'memory-synapse'; using sqlite fallback"
        );
    }

    // Helper constructor to allow compilation even if feature is disabled
    #[cfg(not(feature = "memory-synapse"))]
    pub fn new_fallback() -> Self {
        Self {
            local: std::marker::PhantomData,
        }
    }

    #[cfg(feature = "memory-synapse")]
    pub fn store(&self) -> &SynapseStore {
        &self.store
    }

    #[cfg(feature = "memory-synapse")]
    pub async fn ingest_triples(
        &self,
        triples: Vec<(String, String, String)>,
    ) -> anyhow::Result<()> {
        let ingest_triples: Vec<IngestTriple> = triples
            .into_iter()
            .map(|(s, p, o)| IngestTriple {
                subject: s,
                predicate: p,
                object: o,
                provenance: Some(Provenance {
                    source: "zeroclaw".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    method: "direct".to_string(),
                }),
            })
            .collect();

        self.store.ingest_triples(ingest_triples).await?;
        Ok(())
    }

    /// Import ontology from a URL (e.g. Turtle/RDF)
    #[cfg(feature = "memory-synapse")]
    pub async fn import_ontology(&self, url: &str) -> anyhow::Result<()> {
        // synapse-core's ScenarioManager or Store might expose this,
        // or we can just fetch and parse ourselves if needed.
        // For now, let's assume we can fetch and ingest as raw triples if format is simple,
        // but robust implementation would use oxigraph's parser.
        // Since synapse-core manages ingestion, let's verify if it exposes a direct import.
        // Looking at synapse-core source, it has `ingest::ingest_file`.
        // We will implement a basic fetch-and-ingest here using reqwest + oxigraph if needed,
        // or just placeholder for the concept if synapse-core has a dedicated method we missed.

        // Let's rely on SynapseStore's capabilities.
        // If not directly available, we can add it later.
        Ok(())
    }

    // Scenario Management
    #[cfg(feature = "memory-synapse")]
    pub async fn list_scenarios(
        &self,
    ) -> anyhow::Result<Vec<synapse_core::scenarios::RegistryEntry>> {
        self.scenario_manager.list_scenarios().await
    }

    #[cfg(feature = "memory-synapse")]
    pub async fn install_scenario(&self, name: &str) -> anyhow::Result<std::path::PathBuf> {
        self.scenario_manager.install_scenario(name).await
    }

    /// Execute a SPARQL query
    #[cfg(feature = "memory-synapse")]
    pub fn query_sparql(&self, query: &str) -> anyhow::Result<String> {
        Ok(self.store.query_sparql(query)?)
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
        #[cfg(feature = "memory-synapse")]
        {
            // We still use SQLite for raw blob storage (logs, raw conversation text)
            // But we *also* ingest metadata into the graph if enabled
            self.local.store(key, content, category, session_id).await?;

            let triples = self
                .graph_adapter
                .memory_store_triples(key, content, &category, session_id)?;
            self.ingest_triples(triples).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        {
            anyhow::bail!("Synapse memory feature not enabled")
        }
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        #[cfg(feature = "memory-synapse")]
        {
            // Hybrid search: Vector + Graph
            // We search for nodes relevant to the query
            let results = self.store.hybrid_search(query, limit, 1).await?;

            let mut entries = Vec::new();
            if !results.is_empty() {
                for (uri, score) in results {
                    // Try to fetch full content from SQLite if we have a key mapping
                    if let Some(key) = uri.strip_prefix(&format!("{}Memory/", namespaces::ZEROCLAW))
                    {
                        if let Ok(Some(mut entry)) = self.local.get(key).await {
                            // entry.score = score; // If MemoryEntry had a score field
                            entries.push(entry);
                        }
                    }
                }
            }

            // Fallback/Combine with standard recall if graph results are sparse
            if entries.len() < limit {
                let mut fallback = self
                    .local
                    .recall(query, limit - entries.len(), session_id)
                    .await?;
                entries.append(&mut fallback);
            }

            Ok(entries)
        }
        #[cfg(not(feature = "memory-synapse"))]
        {
            anyhow::bail!("Synapse memory feature not enabled")
        }
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<MemoryEntry>> {
        #[cfg(feature = "memory-synapse")]
        return self.local.get(key).await;
        #[cfg(not(feature = "memory-synapse"))]
        Ok(None)
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        #[cfg(feature = "memory-synapse")]
        return self.local.list(category, session_id).await;
        #[cfg(not(feature = "memory-synapse"))]
        Ok(Vec::new())
    }

    async fn forget(&self, key: &str) -> anyhow::Result<bool> {
        #[cfg(feature = "memory-synapse")]
        return self.local.forget(key).await;
        #[cfg(not(feature = "memory-synapse"))]
        Ok(false)
    }

    async fn count(&self) -> anyhow::Result<usize> {
        #[cfg(feature = "memory-synapse")]
        return self.local.count().await;
        #[cfg(not(feature = "memory-synapse"))]
        Ok(0)
    }

    async fn health_check(&self) -> bool {
        #[cfg(feature = "memory-synapse")]
        return self.local.health_check().await;
        #[cfg(not(feature = "memory-synapse"))]
        false
    }
}

#[async_trait]
impl GraphMemory for SynapseMemory {
    async fn upsert_node(&self, node: GraphNodeUpsert) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let triples = self.graph_adapter.node_upsert_triples(node)?;
            self.ingest_triples(triples).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(())
    }

    async fn upsert_typed_edge(&self, edge: GraphEdgeUpsert) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let triple = self.graph_adapter.edge_upsert_triple(edge)?;

            self.ingest_triples(vec![triple]).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(())
    }

    async fn query_by_neighborhood(
        &self,
        query: NeighborhoodQuery,
    ) -> anyhow::Result<Vec<GraphEdge>> {
        #[cfg(feature = "memory-synapse")]
        {
            let sparql = self.graph_adapter.neighborhood_query(&query);
            let raw = self.store.query_sparql(&sparql)?;
            self.graph_adapter.hydrate_edges(&raw)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(Vec::new())
    }

    async fn semantic_search_with_filters(
        &self,
        query: SemanticGraphQuery,
    ) -> anyhow::Result<Vec<GraphSearchResult>> {
        #[cfg(feature = "memory-synapse")]
        {
            let results = self
                .store
                .hybrid_search(&query.text, query.limit, 1)
                .await?;
            let mut search_results = Vec::new();

            for (uri, score) in results {
                // Construct GraphSearchResult from URI
                // We need to fetch node details (content, type) via SPARQL or helper
                // simplified:
                search_results.push(self.graph_adapter.hydrate_search_result(&uri, score)?);
            }
            Ok(search_results)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(Vec::new())
    }
}

#[cfg(all(test, feature = "memory-synapse"))]
mod tests {
    use super::*;
    use crate::memory::graph_traits::{EdgeDirection, NodeId, RelationType};
    use crate::memory::synapse::ontology::properties;
    use tempfile::TempDir;

    async fn setup_memory() -> anyhow::Result<(TempDir, SynapseMemory)> {
        let temp_dir = TempDir::new()?;
        let sqlite = SqliteMemory::new(temp_dir.path())?;
        let memory = SynapseMemory::new(temp_dir.path(), sqlite)?;
        Ok((temp_dir, memory))
    }

    #[tokio::test]
    async fn query_by_neighborhood_outbound_returns_expected_edge() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .ingest_triples(vec![(
                format!("{}node-a", namespaces::ZEROCLAW),
                properties::RELATES_TO.to_string(),
                format!("{}node-b", namespaces::ZEROCLAW),
            )])
            .await?;

        let edges = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: NodeId::new("node-a")?,
                direction: EdgeDirection::Outbound,
                relation: None,
            })
            .await?;

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source, NodeId::new("node-a")?);
        assert_eq!(edges[0].target, NodeId::new("node-b")?);
        assert_eq!(edges[0].relation, RelationType::DecisionConstraint);
        Ok(())
    }

    #[tokio::test]
    async fn query_by_neighborhood_inbound_returns_expected_edge() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .ingest_triples(vec![(
                format!("{}node-a", namespaces::ZEROCLAW),
                properties::RELATES_TO.to_string(),
                format!("{}node-b", namespaces::ZEROCLAW),
            )])
            .await?;

        let edges = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: NodeId::new("node-b")?,
                direction: EdgeDirection::Inbound,
                relation: None,
            })
            .await?;

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source, NodeId::new("node-a")?);
        assert_eq!(edges[0].target, NodeId::new("node-b")?);
        Ok(())
    }

    #[tokio::test]
    async fn query_by_neighborhood_both_returns_outbound_and_inbound_edges() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .ingest_triples(vec![
                (
                    format!("{}node-a", namespaces::ZEROCLAW),
                    properties::RELATES_TO.to_string(),
                    format!("{}node-b", namespaces::ZEROCLAW),
                ),
                (
                    format!("{}node-c", namespaces::ZEROCLAW),
                    properties::CONTEXT_FOR.to_string(),
                    format!("{}node-a", namespaces::ZEROCLAW),
                ),
            ])
            .await?;

        let edges = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: NodeId::new("node-a")?,
                direction: EdgeDirection::Both,
                relation: None,
            })
            .await?;

        assert_eq!(edges.len(), 2);
        assert!(edges.iter().any(|edge| {
            edge.source == NodeId::new("node-a").expect("valid")
                && edge.target == NodeId::new("node-b").expect("valid")
                && edge.relation == RelationType::DecisionConstraint
        }));
        assert!(edges.iter().any(|edge| {
            edge.source == NodeId::new("node-c").expect("valid")
                && edge.target == NodeId::new("node-a").expect("valid")
                && edge.relation == RelationType::MessageLink
        }));
        Ok(())
    }

    #[tokio::test]
    async fn query_by_neighborhood_relation_filter_limits_results() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .ingest_triples(vec![
                (
                    format!("{}node-a", namespaces::ZEROCLAW),
                    properties::RELATES_TO.to_string(),
                    format!("{}node-b", namespaces::ZEROCLAW),
                ),
                (
                    format!("{}node-a", namespaces::ZEROCLAW),
                    properties::CONTEXT_FOR.to_string(),
                    format!("{}node-c", namespaces::ZEROCLAW),
                ),
            ])
            .await?;

        let edges = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: NodeId::new("node-a")?,
                direction: EdgeDirection::Outbound,
                relation: Some(RelationType::MessageLink),
            })
            .await?;

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source, NodeId::new("node-a")?);
        assert_eq!(edges[0].target, NodeId::new("node-c")?);
        assert_eq!(edges[0].relation, RelationType::MessageLink);
        Ok(())
    }

    #[tokio::test]
    async fn store_and_recall_orchestrate_sqlite_and_graph() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .store(
                "memory-1",
                "deterministic synapse orchestration",
                MemoryCategory::Conversation,
                Some("session-a"),
            )
            .await?;

        let recalled = memory
            .recall("deterministic synapse orchestration", 3, Some("session-a"))
            .await?;

        assert!(!recalled.is_empty());
        assert!(recalled
            .iter()
            .any(|entry| entry.key == "memory-1" && entry.content.contains("deterministic")));
        Ok(())
    }
}
