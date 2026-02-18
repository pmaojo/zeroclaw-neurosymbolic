pub mod ontology;

use super::graph_traits::{
    GraphEdge, GraphEdgeUpsert, GraphMemory, GraphNode, GraphNodeUpsert, GraphSearchResult,
    NeighborhoodQuery, NodeId, RelationType, SemanticGraphQuery, SynapseNodeType,
};
#[cfg(feature = "memory-synapse")]
use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use async_trait::async_trait;
#[cfg(feature = "memory-synapse")]
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

// Conditional compilation imports
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, namespaces, properties};
#[cfg(feature = "memory-synapse")]
use oxigraph::io::{GraphFormat, GraphParser};
#[cfg(feature = "memory-synapse")]
use reqwest::header::CONTENT_TYPE;
#[cfg(feature = "memory-synapse")]
use synapse_core::scenarios::ScenarioManager;
#[cfg(feature = "memory-synapse")]
use synapse_core::store::{IngestTriple, Provenance, SynapseStore};

#[cfg(feature = "memory-synapse")]
const MAX_ONTOLOGY_FILE_BYTES: usize = 5 * 1024 * 1024;
#[cfg(feature = "memory-synapse")]
const MAX_ONTOLOGY_TRIPLES: usize = 50_000;

#[cfg(feature = "memory-synapse")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OntologyImportFormat {
    Turtle,
    RdfXml,
}

#[cfg(feature = "memory-synapse")]
impl OntologyImportFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Turtle => "turtle",
            Self::RdfXml => "rdf+xml",
        }
    }

    fn graph_format(self) -> GraphFormat {
        match self {
            Self::Turtle => GraphFormat::Turtle,
            Self::RdfXml => GraphFormat::RdfXml,
        }
    }

    fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "ttl" => Some(Self::Turtle),
            "rdf" | "owl" | "xml" => Some(Self::RdfXml),
            _ => None,
        }
    }

    fn from_content_type(content_type: &str) -> Option<Self> {
        let mime = content_type
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        match mime {
            "text/turtle" | "application/x-turtle" => Some(Self::Turtle),
            "application/rdf+xml" => Some(Self::RdfXml),
            _ => None,
        }
    }
}

#[cfg(feature = "memory-synapse")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OntologyImportSummary {
    pub imported_triples: usize,
    pub format: OntologyImportFormat,
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

    /// Import ontology from a URL or local file path.
    #[cfg(feature = "memory-synapse")]
    pub async fn import_ontology(&self, source: &str) -> anyhow::Result<OntologyImportSummary> {
        let (payload, format, provenance_source) =
            if source.starts_with("http://") || source.starts_with("https://") {
                self.load_remote_ontology(source).await?
            } else {
                self.load_local_ontology(source)?
            };

        let triples = Self::parse_ontology_triples(&payload, format, &provenance_source)?;
        let imported_triples = triples.len();
        self.store.ingest_triples(triples).await.map_err(|err| {
            anyhow::anyhow!("failed to ingest ontology triples from {provenance_source}: {err}")
        })?;

        tracing::info!(
            source = %provenance_source,
            format = format.as_str(),
            imported_triples,
            "ontology import completed"
        );

        Ok(OntologyImportSummary {
            imported_triples,
            format,
        })
    }

    #[cfg(feature = "memory-synapse")]
    async fn load_remote_ontology(
        &self,
        source: &str,
    ) -> anyhow::Result<(Vec<u8>, OntologyImportFormat, String)> {
        let url = reqwest::Url::parse(source)
            .map_err(|err| anyhow::anyhow!("invalid ontology URL '{source}': {err}"))?;
        let extension_format = url
            .path_segments()
            .and_then(|segments| segments.last())
            .and_then(|name| name.rsplit('.').next())
            .and_then(OntologyImportFormat::from_extension);

        let response = reqwest::get(url.clone())
            .await
            .map_err(|err| anyhow::anyhow!("failed to fetch ontology URL '{source}': {err}"))?;
        if !response.status().is_success() {
            anyhow::bail!(
                "failed to fetch ontology URL '{source}': HTTP {}",
                response.status()
            );
        }

        let content_type_format = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|header| header.to_str().ok())
            .and_then(OntologyImportFormat::from_content_type);

        let format = Self::resolve_import_format(extension_format, content_type_format, source)?;

        if let Some(content_length) = response.content_length() {
            if content_length > MAX_ONTOLOGY_FILE_BYTES as u64 {
                anyhow::bail!(
                    "ontology payload exceeds max size ({} bytes > {} bytes) for source '{source}'",
                    content_length,
                    MAX_ONTOLOGY_FILE_BYTES
                );
            }
        }

        let bytes = response.bytes().await.map_err(|err| {
            anyhow::anyhow!("failed to read ontology payload from '{source}': {err}")
        })?;

        if bytes.len() > MAX_ONTOLOGY_FILE_BYTES {
            anyhow::bail!(
                "ontology payload exceeds max size ({} bytes > {} bytes) for source '{source}'",
                bytes.len(),
                MAX_ONTOLOGY_FILE_BYTES
            );
        }

        Ok((bytes.to_vec(), format, source.to_string()))
    }

    #[cfg(feature = "memory-synapse")]
    fn load_local_ontology(
        &self,
        source: &str,
    ) -> anyhow::Result<(Vec<u8>, OntologyImportFormat, String)> {
        let path = Path::new(source);
        let metadata = std::fs::metadata(path)
            .map_err(|err| anyhow::anyhow!("failed to access ontology file '{source}': {err}"))?;

        if metadata.len() > MAX_ONTOLOGY_FILE_BYTES as u64 {
            anyhow::bail!(
                "ontology file exceeds max size ({} bytes > {} bytes) for source '{source}'",
                metadata.len(),
                MAX_ONTOLOGY_FILE_BYTES
            );
        }

        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!("unsupported ontology format for '{source}': missing extension")
            })?;

        let format = OntologyImportFormat::from_extension(extension).ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported ontology format for '{source}': expected one of .ttl, .rdf, .owl, .xml"
            )
        })?;

        let payload = std::fs::read(path)
            .map_err(|err| anyhow::anyhow!("failed to read ontology file '{source}': {err}"))?;

        Ok((payload, format, source.to_string()))
    }

    #[cfg(feature = "memory-synapse")]
    fn resolve_import_format(
        extension_format: Option<OntologyImportFormat>,
        content_type_format: Option<OntologyImportFormat>,
        source: &str,
    ) -> anyhow::Result<OntologyImportFormat> {
        match (extension_format, content_type_format) {
            (Some(ext), Some(header)) if ext != header => anyhow::bail!(
                "unsupported ontology format for '{source}': extension and content-type disagree"
            ),
            (Some(ext), _) => Ok(ext),
            (None, Some(header)) => Ok(header),
            (None, None) => anyhow::bail!(
                "unsupported ontology format for '{source}': expected Turtle or RDF/XML"
            ),
        }
    }

    #[cfg(feature = "memory-synapse")]
    fn parse_ontology_triples(
        payload: &[u8],
        format: OntologyImportFormat,
        provenance_source: &str,
    ) -> anyhow::Result<Vec<IngestTriple>> {
        let parser = GraphParser::from_format(format.graph_format());
        let reader = std::io::Cursor::new(payload);
        let mut ingest_triples = Vec::new();

        for triple_result in parser.read_triples(reader).map_err(|err| {
            anyhow::anyhow!(
                "failed to parse ontology content for '{provenance_source}' as {}: {err}",
                format.as_str()
            )
        })? {
            let triple = triple_result.map_err(|err| {
                anyhow::anyhow!(
                    "failed to parse ontology triple for '{provenance_source}' as {}: {err}",
                    format.as_str()
                )
            })?;

            let subject = match &triple.subject {
                oxigraph::model::Subject::NamedNode(node) => node.to_string(),
                _ => anyhow::bail!(
                    "unsupported ontology subject term in '{provenance_source}': only named nodes are allowed"
                ),
            };

            let object = match &triple.object {
                oxigraph::model::Term::NamedNode(node) => node.to_string(),
                _ => anyhow::bail!(
                    "unsupported ontology object term in '{provenance_source}': only named nodes are allowed"
                ),
            };

            ingest_triples.push(IngestTriple {
                subject,
                predicate: triple.predicate.to_string(),
                object,
                provenance: Some(Provenance {
                    source: provenance_source.to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    method: "ontology_import".to_string(),
                }),
            });

            if ingest_triples.len() > MAX_ONTOLOGY_TRIPLES {
                anyhow::bail!(
                    "ontology triple count exceeds max limit ({} > {}) for source '{provenance_source}'",
                    ingest_triples.len(),
                    MAX_ONTOLOGY_TRIPLES
                );
            }
        }

        Ok(ingest_triples)
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
    fn node_id_from_uri(uri: &str) -> anyhow::Result<NodeId> {
        let normalized = uri.trim().trim_start_matches('<').trim_end_matches('>');
        let raw_id = normalized
            .strip_prefix(namespaces::ZEROCLAW)
            .ok_or_else(|| {
                anyhow::anyhow!("expected node URI in zeroclaw namespace, got: {uri}")
            })?;
        NodeId::new(raw_id)
    }

    #[cfg(feature = "memory-synapse")]
    fn parse_graph_edge_binding(row: &Value) -> anyhow::Result<GraphEdge> {
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
            source: Self::node_id_from_uri(source_uri)?,
            target: Self::node_id_from_uri(target_uri)?,
            relation: Self::predicate_to_relation(predicate_uri.trim_matches(['<', '>']))?,
        })
    }
}

#[cfg(feature = "memory-synapse")]
fn build_neighborhood_query(query: &NeighborhoodQuery) -> String {
    let anchor_uri = format!("<{}{}>", namespaces::ZEROCLAW, query.anchor.as_str());
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
            let node_uri = format!("{}{}", namespaces::ZEROCLAW, node.id.as_str());

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

            let predicate = Self::relation_to_predicate(&edge.relation);

            self.ingest_triples(vec![(s_uri, predicate, o_uri)]).await?;
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
            let results = self
                .store
                .hybrid_search(&query.text, query.limit, 1)
                .await?;
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
                        content: "loaded from synapse".into(),  // fetch actual content
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

#[cfg(all(test, feature = "memory-synapse"))]
mod tests {
    use super::*;
    use crate::memory::graph_traits::EdgeDirection;
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

    fn fixture_path(name: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("assets")
            .join("ontologies")
            .join(name)
            .to_string_lossy()
            .to_string()
    }

    #[tokio::test]
    async fn import_ontology_successfully_ingests_triples() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        let summary = memory
            .import_ontology(&fixture_path("valid_ontology.ttl"))
            .await?;

        assert_eq!(summary.format, OntologyImportFormat::Turtle);
        assert_eq!(summary.imported_triples, 2);

        let result = memory.query_sparql("SELECT (COUNT(*) AS ?count) WHERE { ?s ?p ?o }")?;
        assert!(result.contains("\"count\":\"2\""));

        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_rejects_unsupported_format() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;
        let temp_file = tempfile::NamedTempFile::new()?;
        let path = temp_file.path().with_extension("json");
        std::fs::write(&path, b"{}")?;

        let error = memory
            .import_ontology(path.to_string_lossy().as_ref())
            .await
            .expect_err("unsupported extension should fail");

        assert!(error.to_string().contains("unsupported ontology format"));

        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_fails_on_parse_errors() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        let error = memory
            .import_ontology(&fixture_path("invalid_ontology.ttl"))
            .await
            .expect_err("invalid TTL should fail parse");

        assert!(error.to_string().contains("failed to parse ontology"));

        Ok(())
    }

    #[tokio::test]
    async fn import_ontology_fails_fast_on_partial_ingest_payload() -> anyhow::Result<()> {
        let (_tmp, memory) = setup_memory().await?;

        let error = memory
            .import_ontology(&fixture_path("literal_object_ontology.ttl"))
            .await
            .expect_err("literal object should fail conversion before ingestion");

        assert!(error
            .to_string()
            .contains("unsupported ontology object term"));

        let result = memory.query_sparql("SELECT (COUNT(*) AS ?count) WHERE { ?s ?p ?o }")?;
        assert!(result.contains("\"count\":\"0\""));

        Ok(())
    }
}
