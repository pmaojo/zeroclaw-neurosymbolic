#[cfg(feature = "memory-synapse")]
pub mod ontology;

use super::graph_traits::{
    GraphEdge, GraphEdgeUpsert, GraphNode, GraphNodeUpsert, GraphSearchResult,
    NeighborhoodQuery, NodeId, RelationType, SemanticGraphQuery, SynapseNodeType,
};
#[cfg(feature = "memory-synapse")]
use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use crate::config::SynapseSourcePolicyConfig;
use async_trait::async_trait;
#[cfg(feature = "memory-synapse")]
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

// Conditional compilation imports
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, namespaces, properties};
#[cfg(feature = "memory-synapse")]
use synapse_core::scenarios::{ScenarioManager, ScenarioSourcePolicy};
#[cfg(feature = "memory-synapse")]
use synapse_core::store::{IngestTriple, Provenance, SynapseStore};

#[cfg(feature = "memory-synapse")]
const MAX_ONTOLOGY_IMPORT_BYTES: u64 = 5 * 1024 * 1024;

#[cfg(feature = "memory-synapse")]
#[derive(Debug, Clone, Copy)]
enum OntologyImportFormat {
    Turtle,
    RdfXml,
}

#[cfg(feature = "memory-synapse")]
impl OntologyImportFormat {
    fn from_path(path: &Path) -> anyhow::Result<Self> {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "ontology file must include a supported extension (.ttl, .rdf, .xml)"
                )
            })?;

        match extension.as_str() {
            "ttl" => Ok(Self::Turtle),
            "rdf" | "xml" => Ok(Self::RdfXml),
            _ => anyhow::bail!(
                "unsupported ontology format '{}'; only Turtle (.ttl) and RDF/XML (.rdf, .xml) are accepted",
                extension
            ),
        }
    }

    fn parser(self) -> oxigraph::io::GraphParser {
        match self {
            Self::Turtle => {
                oxigraph::io::GraphParser::from_format(oxigraph::io::GraphFormat::Turtle)
            }
            Self::RdfXml => {
                oxigraph::io::GraphParser::from_format(oxigraph::io::GraphFormat::RdfXml)
            }
        }
    }

    fn method_label(self) -> &'static str {
        match self {
            Self::Turtle => "ontology_import_turtle",
            Self::RdfXml => "ontology_import_rdf_xml",
        }
    }
}

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
    pub fn new(
        workspace_dir: &Path,
        local: SqliteMemory,
        source_policy: SynapseSourcePolicyConfig,
    ) -> anyhow::Result<Self> {
        let namespace = "zeroclaw";
        // SynapseStore expects the parent directory path
        let store = SynapseStore::open(namespace, workspace_dir.to_str().unwrap())?;

        let scenario_policy = ScenarioSourcePolicy {
            allow_remote_scenarios: source_policy.allow_remote_scenarios,
            allowed_registry_hosts: source_policy.allowed_registry_hosts,
            max_download_size_bytes: source_policy.max_download_size_bytes,
        };
        let scenario_manager = ScenarioManager::with_policy(workspace_dir, scenario_policy);

        Ok(Self {
            local,
            store: Arc::new(store),
            scenario_manager: Arc::new(scenario_manager),
        })
    }

    #[cfg(not(feature = "memory-synapse"))]
    pub fn new(
        workspace_dir: &Path,
        _local: super::sqlite::SqliteMemory,
        _source_policy: SynapseSourcePolicyConfig,
    ) -> anyhow::Result<Self> {
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
    pub fn get_store(&self) -> &SynapseStore {
        &self.store
    }

    #[cfg(feature = "memory-synapse")]
    pub async fn ingest_triples_local(
        &self,
        triples: Vec<(String, String, String)>,
    ) -> anyhow::Result<()> {
        let ingest_triples: Vec<IngestTriple> = triples
            .into_iter()
            .map(|(s, p, o)| IngestTriple {
                subject: s,
                predicate: p,
                object: o,
                provenance: None,
            })
            .collect();

        self.store.ingest_triples(ingest_triples).await?;
        Ok(())
    }

    /// Import ontology from a URL (e.g. Turtle/RDF)
    #[cfg(feature = "memory-synapse")]
    pub async fn import_ontology(&self, url: &str) -> anyhow::Result<()> {
        let path = if let Some(path) = url.strip_prefix("file://") {
            std::path::PathBuf::from(path)
        } else if url.starts_with("http://") || url.starts_with("https://") {
            anyhow::bail!(
                "remote ontology imports are not supported in this runtime path; use a local file path"
            );
        } else {
            std::path::PathBuf::from(url)
        };

        if !path.exists() {
            anyhow::bail!("ontology file does not exist: {}", path.display());
        }

        if !path.is_file() {
            anyhow::bail!(
                "ontology import path must point to a file: {}",
                path.display()
            );
        }

        let format = OntologyImportFormat::from_path(&path)?;
        let metadata = tokio::fs::metadata(&path).await?;
        if metadata.len() > MAX_ONTOLOGY_IMPORT_BYTES {
            anyhow::bail!(
                "ontology file '{}' exceeds max allowed size of {} bytes",
                path.display(),
                MAX_ONTOLOGY_IMPORT_BYTES
            );
        }

        let parse_file = std::fs::File::open(&path)?;
        let parser = format.parser();
        let import_timestamp = chrono::Utc::now().to_rfc3339();
        let provenance_source = path.display().to_string();
        let mut parsed_triples = Vec::new();

        for triple_result in parser.read_triples(std::io::BufReader::new(parse_file))? {
            let triple = triple_result.map_err(|error| {
                anyhow::anyhow!(
                    "ontology parsing failed for '{}': {}",
                    path.display(),
                    error
                )
            })?;

            parsed_triples.push(IngestTriple {
                subject: triple.subject.to_string(),
                predicate: triple.predicate.to_string(),
                object: triple.object.to_string(),
                provenance: Some(Provenance {
                    source: provenance_source.clone(),
                    timestamp: import_timestamp.clone(),
                    method: format.method_label().to_string(),
                }),
            });
        }

        if parsed_triples.is_empty() {
            anyhow::bail!(
                "ontology '{}' did not contain any triples; refusing empty import",
                path.display()
            );
        }

        self.store.ingest_triples(parsed_triples).await?;
        Ok(())
    }

    // Scenario Management
    #[cfg(feature = "memory-synapse")]
    pub async fn list_scenarios(
        &self,
    ) -> anyhow::Result<Vec<synapse_core::scenarios::RegistryEntry>> {
        tracing::info!(
            operation = "synapse_list_scenarios",
            "Listing Synapse scenarios with configured source policy"
        );
        self.scenario_manager.list_scenarios().await
    }

    #[cfg(feature = "memory-synapse")]
    pub async fn install_scenario(&self, name: &str) -> anyhow::Result<std::path::PathBuf> {
        tracing::info!(
            operation = "synapse_install_scenario",
            scenario = name,
            "Installing Synapse scenario with configured source policy"
        );
        self.scenario_manager.install_scenario(name).await
    }

    /// Execute a SPARQL query
    #[cfg(feature = "memory-synapse")]
    pub fn query_sparql_local(&self, query: &str) -> anyhow::Result<String> {
        Ok(self.store.query_sparql(query)?)
    }

    #[cfg(feature = "memory-synapse")]
    fn relation_to_predicate(relation: &RelationType) -> String {
        match relation {
            RelationType::CategoryMembership => namespaces::RDF.to_owned() + "type",
            RelationType::DecisionConstraint => properties::RELATES_TO.to_string(),
            RelationType::MessageLink => properties::CONTEXT_FOR.to_string(),
            RelationType::Custom(value) => format!("{}{}", namespaces::ZEROCLAW, value),
        }
    }

    #[cfg(feature = "memory-synapse")]
    fn predicate_to_relation(predicate: &str) -> anyhow::Result<RelationType> {
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

    #[cfg(feature = "memory-synapse")]
    fn uri_to_node_id(uri: &str) -> anyhow::Result<NodeId> {
        let normalized = uri.trim().trim_start_matches('<').trim_end_matches('>');
        let raw_id = normalized
            .strip_prefix(namespaces::ZEROCLAW)
            .ok_or_else(|| {
                anyhow::anyhow!("expected node URI in zeroclaw namespace, got: {uri}")
            })?;
        if raw_id.trim().is_empty() {
            anyhow::bail!("node URI suffix cannot be empty: {uri}");
        }
        NodeId::new(raw_id)
    }

    #[cfg(feature = "memory-synapse")]
    fn node_id_to_uri(id: &NodeId) -> String {
        format!("{}{}", namespaces::ZEROCLAW, id.as_str())
    }

    #[cfg(feature = "memory-synapse")]
    fn parse_graph_edge_binding(row: &Value) -> anyhow::Result<GraphEdge> {
        let source_uri = row
            .get("source")
            .or_else(|| row.get("?source"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'source' binding in SPARQL row: {row}"))?;
        let predicate_uri = row
            .get("predicate")
            .or_else(|| row.get("?predicate"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'predicate' binding in SPARQL row: {row}"))?;
        let target_uri = row
            .get("target")
            .or_else(|| row.get("?target"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'target' binding in SPARQL row: {row}"))?;

        Ok(GraphEdge {
            source: Self::uri_to_node_id(source_uri)?,
            target: Self::uri_to_node_id(target_uri)?,
            relation: Self::predicate_to_relation(predicate_uri.trim_matches(['<', '>']))?,
        })
    }

    #[cfg(feature = "memory-synapse")]
    fn class_to_node_type(class_uri: &str) -> anyhow::Result<SynapseNodeType> {
        match class_uri {
            classes::AGENT => Ok(SynapseNodeType::Agent),
            classes::DECISION_RULE => Ok(SynapseNodeType::DecisionRule),
            classes::CONVERSATION => Ok(SynapseNodeType::MemoryConversation),
            classes::MEMORY => Ok(SynapseNodeType::MemoryCore),
            _ => anyhow::bail!("unsupported node class URI: {class_uri}"),
        }
    }

    #[cfg(feature = "memory-synapse")]
    fn parse_agent_role(raw: &str) -> anyhow::Result<Option<super::graph_traits::AgentRole>> {
        let normalized = raw.trim_matches(['<', '>', '"']).to_ascii_lowercase();
        let role = match normalized.as_str() {
            "" => None,
            "user" => Some(super::graph_traits::AgentRole::User),
            "assistant" => Some(super::graph_traits::AgentRole::Assistant),
            "system" => Some(super::graph_traits::AgentRole::System),
            "tool" => Some(super::graph_traits::AgentRole::Tool),
            _ => anyhow::bail!("unsupported agent role value: {raw}"),
        };
        Ok(role)
    }

    #[cfg(feature = "memory-synapse")]
    fn hydrate_graph_node(&self, uri: &str) -> anyhow::Result<GraphNode> {
        let clean_uri = uri.trim().trim_start_matches('<').trim_end_matches('>');
        let query = format!(
            "SELECT ?predicate ?object WHERE {{ <{}> ?predicate ?object . }} ORDER BY ?predicate",
            clean_uri
        );
        let raw = self.store.query_sparql(&query)?;
        let rows: Vec<Value> = serde_json::from_str(&raw)?;

        let mut node_type = None;
        let mut content = None;
        let mut agent_role = None;

        for row in rows {
            let predicate = row
                .get("predicate")
                .or_else(|| row.get("?predicate"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing predicate binding: {row}"))?
                .trim_matches(['<', '>']);
            let object = row
                .get("object")
                .or_else(|| row.get("?object"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing object binding: {row}"))?;

            if predicate == (namespaces::RDF.to_owned() + "type") {
                node_type = Some(Self::class_to_node_type(object.trim_matches(['<', '>']))?);
                continue;
            }
            if predicate == properties::HAS_CONTENT {
                content = Some(object.trim_matches('"').to_string());
                continue;
            }
            if predicate == properties::HAS_ROLE {
                agent_role = Self::parse_agent_role(object)?;
            }
        }

        Ok(GraphNode {
            id: Self::uri_to_node_id(clean_uri)?,
            node_type: node_type.ok_or_else(|| {
                anyhow::anyhow!("missing rdf:type triple while hydrating node: {clean_uri}")
            })?,
            content: content.ok_or_else(|| {
                anyhow::anyhow!("missing hasContent triple while hydrating node: {clean_uri}")
            })?,
            agent_role,
            decision_rule_id: None,
        })
    }
}

#[cfg(feature = "memory-synapse")]
fn build_neighborhood_query(query: &NeighborhoodQuery) -> String {
    let anchor_uri = format!("<{}>", SynapseMemory::node_id_to_uri(&query.anchor));
    let relation_filter = query
        .relation
        .as_ref()
        .map(SynapseMemory::relation_to_predicate)
        .map(|predicate| format!("VALUES ?predicate {{ <{}> }}", predicate))
        .unwrap_or_default();

    let where_clause = match query.direction {
        super::graph_traits::EdgeDirection::Outbound => {
            format!(
                "BIND({anchor} AS ?source)\n?source ?predicate ?target .\nFILTER(isIRI(?target))",
                anchor = anchor_uri
            )
        }
        super::graph_traits::EdgeDirection::Inbound => {
            format!(
                "BIND({anchor} AS ?target)\n?source ?predicate ?target .\nFILTER(isIRI(?source))",
                anchor = anchor_uri
            )
        }
        super::graph_traits::EdgeDirection::Both => {
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
            let type_triple = (
                node_uri.clone(),
                namespaces::RDF.to_owned() + "type",
                classes::MEMORY.to_string(),
            );
            let content_triple = (
                node_uri.clone(),
                properties::HAS_CONTENT.to_string(),
                format!("\"{}\"", content.replace("\"", "\\\"")),
            );

            let mut triples = vec![type_triple, content_triple];

            if let Some(sess) = session_id {
                triples.push((
                    node_uri.clone(),
                    properties::CONTEXT_FOR.to_string(),
                    format!("{}Session/{}", namespaces::ZEROCLAW, sess),
                ));
            }

            self.ingest_triples_local(triples).await?;
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

    async fn upsert_node(&self, node: GraphNodeUpsert) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let node_uri = Self::node_id_to_uri(&node.id);

            // Map SynapseNodeType to RDF Class
            let rdf_class = match node.node_type {
                SynapseNodeType::Agent => classes::AGENT,
                SynapseNodeType::DecisionRule => classes::DECISION_RULE,
                SynapseNodeType::MemoryConversation => classes::CONVERSATION,
                _ => classes::MEMORY, // Default
            };

            let mut triples = vec![
                (
                    node_uri.clone(),
                    namespaces::RDF.to_owned() + "type",
                    rdf_class.to_string(),
                ),
                (
                    node_uri.clone(),
                    properties::HAS_CONTENT.to_string(),
                    format!("\"{}\"", node.content.replace("\"", "\\\"")),
                ),
            ];

            if let Some(role) = node.agent_role {
                triples.push((
                    node_uri.clone(),
                    properties::HAS_ROLE.to_string(),
                    format!("\"{:?}\"", role),
                ));
            }

            self.ingest_triples_local(triples).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(())
    }

    async fn upsert_typed_edge(&self, edge: GraphEdgeUpsert) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let s_uri = Self::node_id_to_uri(&edge.source);
            let o_uri = Self::node_id_to_uri(&edge.target);

            let predicate = Self::relation_to_predicate(&edge.relation);

            self.ingest_triples_local(vec![(s_uri, predicate, o_uri)]).await?;
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
            let sparql = build_neighborhood_query(&query);
            let raw = self.store.query_sparql(&sparql)?;
            let rows: Vec<Value> = serde_json::from_str(&raw)?;

            let mut edges = Vec::with_capacity(rows.len());
            for row in rows {
                edges.push(Self::parse_graph_edge_binding(&row)?);
            }

            Ok(edges)
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
            if query
                .filter
                .as_ref()
                .and_then(|f| f.relation.as_ref())
                .is_some()
            {
                anyhow::bail!(
                    "semantic relation filtering is not yet supported in synapse memory adapter"
                );
            }

            let results = self
                .store
                .hybrid_search(&query.text, query.limit, 1)
                .await?;
            let mut search_results = Vec::new();

            for (uri, score) in results {
                let node = self.hydrate_graph_node(&uri)?;

                if let Some(filter) = &query.filter {
                    if filter
                        .node_type
                        .as_ref()
                        .is_some_and(|expected| expected != &node.node_type)
                    {
                        continue;
                    }
                    if filter
                        .agent_role
                        .as_ref()
                        .is_some_and(|expected| node.agent_role.as_ref() != Some(expected))
                    {
                        continue;
                    }
                    if filter
                        .decision_rule_id
                        .as_ref()
                        .is_some_and(|expected| node.decision_rule_id.as_ref() != Some(expected))
                    {
                        continue;
                    }
                }

                search_results.push(GraphSearchResult { node, score });
            }
            Ok(search_results)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(Vec::new())
    }

    async fn ingest_triples(&self, triples: Vec<(String, String, String)>) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            self.ingest_triples_local(triples).await?;
            Ok(())
        }
        #[cfg(not(feature = "memory-synapse"))]
        {
            let _ = triples;
            anyhow::bail!("Synapse memory feature not enabled")
        }
    }

    async fn query_sparql(&self, query: &str) -> anyhow::Result<String> {
        #[cfg(feature = "memory-synapse")]
        {
            self.query_sparql_local(query)
        }
        #[cfg(not(feature = "memory-synapse"))]
        {
            let _ = query;
            anyhow::bail!("Synapse memory feature not enabled")
        }
    }
}

#[cfg(all(test, feature = "memory-synapse"))]
mod tests {
    use super::*;
    use crate::memory::graph_traits::EdgeDirection;
    use tempfile::TempDir;

    #[test]
    fn uri_to_node_id_roundtrip_valid_uri() -> anyhow::Result<()> {
        let id = NodeId::new("memory/node-1")?;
        let uri = SynapseMemory::node_id_to_uri(&id);
        let parsed = SynapseMemory::uri_to_node_id(&uri)?;

        assert_eq!(parsed, id);
        Ok(())
    }

    #[test]
    fn uri_to_node_id_rejects_empty_tail() {
        let uri = namespaces::ZEROCLAW.to_string();
        let result = SynapseMemory::uri_to_node_id(&uri);

        assert!(result.is_err());
    }

    #[test]
    fn uri_to_node_id_rejects_wrong_namespace() {
        let uri = "https://example.com/node-1";
        let result = SynapseMemory::uri_to_node_id(uri);

        assert!(result.is_err());
    }

    #[test]
    fn uri_to_node_id_roundtrip_with_special_characters() -> anyhow::Result<()> {
        let id = NodeId::new("node with spaces/%25?and=queries#frag")?;
        let uri = SynapseMemory::node_id_to_uri(&id);
        let parsed = SynapseMemory::uri_to_node_id(&uri)?;

        assert_eq!(parsed, id);
        Ok(())
    }

    async fn setup_memory() -> anyhow::Result<(TempDir, SynapseMemory)> {
        let temp_dir = TempDir::new()?;
        let sqlite = SqliteMemory::new(temp_dir.path())?;
        let memory = SynapseMemory::new(
            temp_dir.path(),
            sqlite,
            SynapseSourcePolicyConfig::default(),
        )?;
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
    async fn semantic_search_results_never_use_unknown_node_id() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        memory
            .upsert_node(GraphNodeUpsert {
                id: NodeId::new("search-node")?,
                node_type: SynapseNodeType::MemoryCore,
                content: "searchable semantic memory".to_string(),
                agent_role: None,
                decision_rule_id: None,
            })
            .await?;

        let results = memory
            .semantic_search_with_filters(SemanticGraphQuery {
                text: "searchable".to_string(),
                limit: 10,
                filter: None,
            })
            .await?;

        assert!(!results.is_empty());
        assert!(results
            .iter()
            .all(|result| result.node.id.as_str() != "unknown"));
        Ok(())
    }

    #[test]
    fn hydrate_graph_node_reads_type_content_and_role() -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (_tmp, memory) = setup_memory().await?;

            memory
                .upsert_node(GraphNodeUpsert {
                    id: NodeId::new("agent-node")?,
                    node_type: SynapseNodeType::Agent,
                    content: "agent content".to_string(),
                    agent_role: Some(crate::memory::graph_traits::AgentRole::Assistant),
                    decision_rule_id: None,
                })
                .await?;

            let node = memory.hydrate_graph_node(&format!("{}agent-node", namespaces::ZEROCLAW))?;

            assert_eq!(node.id, NodeId::new("agent-node")?);
            assert_eq!(node.node_type, SynapseNodeType::Agent);
            assert_eq!(node.content, "agent content");
            assert_eq!(
                node.agent_role,
                Some(crate::memory::graph_traits::AgentRole::Assistant)
            );
            Ok(())
        })
    }

    #[tokio::test]
    async fn import_ontology_local_ttl_ingests_triple() -> anyhow::Result<()> {
        let (tmp, memory) = setup_memory().await?;
        let ontology_path = tmp.path().join("sample.ttl");

        tokio::fs::write(
            &ontology_path,
            "<http://zeroclaw.ai/schema#onto-a> <http://zeroclaw.ai/schema#relatesTo> <http://zeroclaw.ai/schema#onto-b> .\n",
        )
        .await?;

        memory
            .import_ontology(
                ontology_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("ontology path is not valid utf-8"))?,
            )
            .await?;

        // Query across all named graphs since import_ontology uses a provenance-based named graph
        let ask_query = format!(
            "ASK {{ GRAPH ?g {{ <{}onto-a> <{}> <{}onto-b> }} }}",
            namespaces::ZEROCLAW,
            properties::RELATES_TO,
            namespaces::ZEROCLAW
        );
        let result = memory.query_sparql(&ask_query).await?;
        assert!(result.contains("true"));

        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_rejects_unsupported_extension() -> anyhow::Result<()> {
        let (tmp, memory) = setup_memory().await?;
        let ontology_path = tmp.path().join("sample.nt");
        tokio::fs::write(
            &ontology_path,
            "<http://zeroclaw.ai/schema#onto-a> <http://zeroclaw.ai/schema#relatesTo> <http://zeroclaw.ai/schema#onto-b> .\n",
        )
        .await?;

        let err = memory
            .import_ontology(
                ontology_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("ontology path is not valid utf-8"))?,
            )
            .await
            .expect_err("unsupported format must fail");

        assert!(
            err.to_string().contains("unsupported ontology format"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_rejects_parse_errors() -> anyhow::Result<()> {
        let (tmp, memory) = setup_memory().await?;
        let ontology_path = tmp.path().join("broken.ttl");
        tokio::fs::write(
            &ontology_path,
            "<http://zeroclaw.ai/schema#onto-a> <http://zeroclaw.ai/schema#relatesTo> .\n",
        )
        .await?;

        let err = memory
            .import_ontology(
                ontology_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("ontology path is not valid utf-8"))?,
            )
            .await
            .expect_err("parse errors must fail");

        assert!(
            err.to_string().contains("ontology parsing failed"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_rejects_oversized_files() -> anyhow::Result<()> {
        let (tmp, memory) = setup_memory().await?;
        let ontology_path = tmp.path().join("too-large.ttl");
        let oversized = "#".repeat(5_242_881);
        tokio::fs::write(&ontology_path, oversized).await?;

        let err = memory
            .import_ontology(
                ontology_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("ontology path is not valid utf-8"))?,
            )
            .await
            .expect_err("oversized ontology must fail");

        assert!(
            err.to_string().contains("exceeds max allowed size"),
            "unexpected error: {err}"
        );
        Ok(())
    }
}
