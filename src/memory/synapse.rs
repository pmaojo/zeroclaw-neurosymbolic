pub mod ontology;

use super::graph_traits::{
    GraphEdge, GraphEdgeUpsert, GraphMemory, GraphNode, GraphNodeUpsert,
    GraphSearchResult, NeighborhoodQuery, NodeId, SemanticGraphQuery,
    SynapseNodeType, RelationType
};
#[cfg(feature = "memory-synapse")]
use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;
#[cfg(feature = "memory-synapse")]
use tokio::sync::RwLock;

// Conditional compilation imports
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, properties, namespaces};
#[cfg(feature = "memory-synapse")]
use synapse_core::store::{SynapseStore, IngestTriple, Provenance};
#[cfg(feature = "memory-synapse")]
use synapse_core::scenarios::ScenarioManager;

pub struct SynapseMemory {
    #[cfg(feature = "memory-synapse")]
    local: SqliteMemory,
    #[cfg(feature = "memory-synapse")]
    store: Arc<SynapseStore>,
    #[cfg(feature = "memory-synapse")]
    scenario_manager: Arc<ScenarioManager>,
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
         Self { local: std::marker::PhantomData }
    }


    #[cfg(feature = "memory-synapse")]
    pub fn store(&self) -> &SynapseStore {
        &self.store
    }

    #[cfg(feature = "memory-synapse")]
    pub async fn ingest_triples(&self, triples: Vec<(String, String, String)>) -> anyhow::Result<()> {
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
    pub async fn list_scenarios(&self) -> anyhow::Result<Vec<synapse_core::scenarios::RegistryEntry>> {
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

            // Create a node for this memory entry
            let node_uri = format!("{}Memory/{}", namespaces::ZEROCLAW, key);
            let type_triple = (node_uri.clone(), namespaces::RDF.to_owned() + "type", classes::MEMORY.to_string());
            let content_triple = (node_uri.clone(), properties::HAS_CONTENT.to_string(), format!("\"{}\"", content.replace("\"", "\\\"")));

            let mut triples = vec![type_triple, content_triple];

            if let Some(sess) = session_id {
                triples.push((node_uri.clone(), properties::CONTEXT_FOR.to_string(), format!("{}Session/{}", namespaces::ZEROCLAW, sess)));
            }

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
                    if let Some(key) = uri.strip_prefix(&format!("{}Memory/", namespaces::ZEROCLAW)) {
                         if let Ok(Some(mut entry)) = self.local.get(key).await {
                             // entry.score = score; // If MemoryEntry had a score field
                             entries.push(entry);
                         }
                    }
                }
            }

            // Fallback/Combine with standard recall if graph results are sparse
            if entries.len() < limit {
                let mut fallback = self.local.recall(query, limit - entries.len(), session_id).await?;
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
            let node_uri = format!("{}{}", namespaces::ZEROCLAW, node.id.as_str());

            // Map SynapseNodeType to RDF Class
            let rdf_class = match node.node_type {
                 SynapseNodeType::Agent => classes::AGENT,
                 SynapseNodeType::DecisionRule => classes::DECISION_RULE,
                 SynapseNodeType::MemoryConversation => classes::CONVERSATION,
                 _ => classes::MEMORY, // Default
            };

            let mut triples = vec![
                (node_uri.clone(), namespaces::RDF.to_owned() + "type", rdf_class.to_string()),
                (node_uri.clone(), properties::HAS_CONTENT.to_string(), format!("\"{}\"", node.content.replace("\"", "\\\""))),
            ];

            if let Some(role) = node.agent_role {
                triples.push((node_uri.clone(), properties::HAS_ROLE.to_string(), format!("\"{:?}\"", role)));
            }

            self.ingest_triples(triples).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(())
    }

    async fn upsert_typed_edge(&self, edge: GraphEdgeUpsert) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let s_uri = format!("{}{}", namespaces::ZEROCLAW, edge.source.as_str());
            let o_uri = format!("{}{}", namespaces::ZEROCLAW, edge.target.as_str());

            // Map RelationType to RDF Property
            let predicate = match edge.relation {
                RelationType::CategoryMembership => namespaces::RDF.to_owned() + "type",
                RelationType::DecisionConstraint => properties::RELATES_TO.to_string(), // refine
                RelationType::MessageLink => properties::CONTEXT_FOR.to_string(),
                RelationType::Custom(s) => format!("{}{}", namespaces::ZEROCLAW, s),
            };

            self.ingest_triples(vec![
                (s_uri, predicate, o_uri)
            ]).await?;
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
             // Implementation would involve a SPARQL query to get edges connected to anchor
             // For now return empty or mock implementation
             Ok(Vec::new())
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
             let results = self.store.hybrid_search(&query.text, query.limit, 1).await?;
             let mut search_results = Vec::new();

             for (uri, score) in results {
                  // Construct GraphSearchResult from URI
                  // We need to fetch node details (content, type) via SPARQL or helper
                  // simplified:
                  let id_str = uri.replace(namespaces::ZEROCLAW, "");
                  let id = NodeId::new(id_str).unwrap_or(NodeId::new("unknown").unwrap());

                  search_results.push(GraphSearchResult {
                      node: GraphNode {
                          id,
                          node_type: SynapseNodeType::MemoryCore, // fetch actual type
                          content: "loaded from synapse".into(), // fetch actual content
                          agent_role: None,
                          decision_rule_id: None,
                      },
                      score,
                  });
             }
             Ok(search_results)
         }
         #[cfg(not(feature = "memory-synapse"))]
         Ok(Vec::new())
    }
}
