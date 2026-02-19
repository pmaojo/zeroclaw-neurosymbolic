use crate::episodic::EpisodicMemory;
use crate::persistence::{load_bincode, save_bincode};
use crate::vector_store::VectorStore;
use anyhow::Result;
use chrono::Utc;
use oxigraph::model::*;
use oxigraph::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

const DEFAULT_MAPPING_SAVE_THRESHOLD: usize = 1000;

/// Persisted URI mappings
#[derive(Serialize, Deserialize, Default)]
struct UriMappings {
    uri_to_id: HashMap<String, u32>,
    next_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub timestamp: String,
    pub method: String,
}

pub struct IngestTriple {
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub provenance: Option<Provenance>,
}

pub struct SynapseStore {
    pub store: Store,
    pub namespace: String,
    pub storage_path: PathBuf,
    // Mapping for gRPC compatibility (ID <-> URI)
    pub id_to_uri: RwLock<HashMap<u32, String>>,
    pub uri_to_id: RwLock<HashMap<String, u32>>,
    pub next_id: std::sync::atomic::AtomicU32,
    // Vector store for hybrid search
    pub vector_store: Option<Arc<VectorStore>>,
    // Persistence state
    dirty_count: AtomicUsize,
    save_threshold: usize,
}

impl SynapseStore {
    pub fn open(namespace: &str, storage_path: &str) -> Result<Self> {
        let path = PathBuf::from(storage_path).join(namespace);
        std::fs::create_dir_all(&path)?;
        let store = Store::open(&path)?;

        // Load persisted URI mappings if they exist
        let mappings_path_bin = path.join("uri_mappings.bin");
        let mappings_path_json = path.join("uri_mappings.json");

        let (uri_to_id, id_to_uri, next_id) = if mappings_path_bin.exists() {
            let mappings: UriMappings = load_bincode(&mappings_path_bin)?;
            let id_to_uri: HashMap<u32, String> = mappings
                .uri_to_id
                .iter()
                .map(|(uri, &id)| (id, uri.clone()))
                .collect();
            (mappings.uri_to_id, id_to_uri, mappings.next_id)
        } else if mappings_path_json.exists() {
            let content = std::fs::read_to_string(&mappings_path_json)?;
            let mappings: UriMappings = serde_json::from_str(&content)?;
            let id_to_uri: HashMap<u32, String> = mappings
                .uri_to_id
                .iter()
                .map(|(uri, &id)| (id, uri.clone()))
                .collect();
            (mappings.uri_to_id, id_to_uri, mappings.next_id)
        } else {
            (HashMap::new(), HashMap::new(), 1)
        };

        // Initialize vector store (optional, can fail gracefully)
        let vector_store = match VectorStore::new(namespace) {
            Ok(vs) => Some(Arc::new(vs)),
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to initialize vector store for namespace '{}': {}",
                    namespace, e
                );
                None
            }
        };

        Ok(Self {
            store,
            namespace: namespace.to_string(),
            storage_path: path,
            id_to_uri: RwLock::new(id_to_uri),
            uri_to_id: RwLock::new(uri_to_id),
            next_id: std::sync::atomic::AtomicU32::new(next_id),
            vector_store,
            dirty_count: AtomicUsize::new(0),
            save_threshold: DEFAULT_MAPPING_SAVE_THRESHOLD,
        })
    }

    /// Save URI mappings to disk
    fn save_mappings(&self) -> Result<()> {
        let mappings = UriMappings {
            uri_to_id: self.uri_to_id.read().unwrap().clone(),
            next_id: self.next_id.load(std::sync::atomic::Ordering::Relaxed),
        };
        // Capture the count before saving? No, we just care that we saved the current state.
        // But if new items are added during save, the dirty count will increment.
        // We need to subtract what we think we saved.
        // Since we save the *entire* map, we effectively save *all* dirty items up to that point.
        // So we can read the dirty count, save, then subtract.
        let current_dirty = self.dirty_count.load(Ordering::Relaxed);

        save_bincode(&self.storage_path.join("uri_mappings.bin"), &mappings)?;

        if current_dirty > 0 {
            let _ = self.dirty_count.fetch_sub(current_dirty, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Force save all data to disk
    pub fn flush(&self) -> Result<()> {
        self.save_mappings()?;
        if let Some(ref vs) = self.vector_store {
            vs.flush()?;
        }
        Ok(())
    }

    pub fn get_or_create_id(&self, uri: &str) -> u32 {
        {
            let map = self.uri_to_id.read().unwrap();
            if let Some(&id) = map.get(uri) {
                return id;
            }
        }

        let mut uri_map = self.uri_to_id.write().unwrap();
        let mut id_map = self.id_to_uri.write().unwrap();

        if let Some(&id) = uri_map.get(uri) {
            return id;
        }

        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        uri_map.insert(uri.to_string(), id);
        id_map.insert(id, uri.to_string());

        drop(uri_map);
        drop(id_map);

        // Check if we need to auto-save mappings
        let count = self.dirty_count.fetch_add(1, Ordering::Relaxed);
        if count + 1 >= self.save_threshold {
            let _ = self.save_mappings();
        }

        id
    }

    pub fn get_uri(&self, id: u32) -> Option<String> {
        self.id_to_uri.read().unwrap().get(&id).cloned()
    }

    pub async fn ingest_triples(&self, triples: Vec<IngestTriple>) -> Result<(u32, u32)> {
        let mut added = 0;

        // Group by provenance to optimize batch insertion into named graphs
        let mut batches: HashMap<Option<Provenance>, Vec<(String, String, String)>> =
            HashMap::new();

        for t in triples {
            batches
                .entry(t.provenance)
                .or_default()
                .push((t.subject, t.predicate, t.object));
        }

        for (prov, batch_triples) in batches {
            let graph_name = if let Some(p) = &prov {
                let uuid = Uuid::new_v4();
                let uri = format!("urn:batch:{}", uuid);

                let batch_node = NamedNode::new_unchecked(&uri);
                let p_derived =
                    NamedNode::new_unchecked("http://www.w3.org/ns/prov#wasDerivedFrom");
                let p_time = NamedNode::new_unchecked("http://www.w3.org/ns/prov#generatedAtTime");
                let p_method = NamedNode::new_unchecked("http://www.w3.org/ns/prov#wasGeneratedBy");

                let o_source = Literal::new_simple_literal(&p.source);
                let o_time = Literal::new_simple_literal(&p.timestamp);
                let o_method = Literal::new_simple_literal(&p.method);

                self.store.insert(&Quad::new(
                    batch_node.clone(),
                    p_derived,
                    o_source,
                    GraphName::DefaultGraph,
                ))?;
                self.store.insert(&Quad::new(
                    batch_node.clone(),
                    p_time,
                    o_time,
                    GraphName::DefaultGraph,
                ))?;
                self.store.insert(&Quad::new(
                    batch_node.clone(),
                    p_method,
                    o_method,
                    GraphName::DefaultGraph,
                ))?;

                // If source is "mcp", put triples in default graph for easier querying
                if p.source == "mcp" {
                    GraphName::DefaultGraph
                } else {
                    GraphName::NamedNode(batch_node)
                }
            } else {
                GraphName::DefaultGraph
            };

            for (s, p, o) in batch_triples {
                let subject_uri = self.ensure_uri(&s);
                let predicate_uri = self.ensure_uri(&p);

                // Register URIs in the ID mapping (for gRPC compatibility)
                self.get_or_create_id(&subject_uri);
                self.get_or_create_id(&predicate_uri);

                let subject = Subject::NamedNode(NamedNode::new_unchecked(&subject_uri));
                let predicate = NamedNode::new_unchecked(&predicate_uri);

                let (object, object_key_str) = if o.starts_with('"') {
                    // It's a literal
                    let value = o.trim_matches('"');
                    // TODO: Support language tags or types if needed
                    (Term::Literal(Literal::new_simple_literal(value)), value.to_string())
                } else {
                    let object_uri = self.ensure_uri(&o);
                    self.get_or_create_id(&object_uri);
                    (Term::NamedNode(NamedNode::new_unchecked(&object_uri)), object_uri)
                };

                let quad = Quad::new(subject, predicate, object, graph_name.clone());
                let inserted = self.store.insert(&quad)?;

                // Also index in vector store if available
                if let Some(ref vs) = self.vector_store {
                    // We check if it's already in the vector store by key
                    let key = format!("{}|{}|{}", subject_uri, predicate_uri, object_key_str);
                    if vs.get_id(&key).is_none() {
                        // Create searchable content from triple
                        let content = format!("{} {} {}", s, p, o);
                        // Pass metadata including the subject URI for graph expansion later
                        let metadata = serde_json::json!({
                            "uri": subject_uri,
                            "predicate": predicate_uri,
                            "object": object_key_str,
                            "type": "triple"
                        });

                        if let Err(e) = vs.add(&key, &content, metadata).await {
                            // If we just inserted it into the graph but vector failed,
                            // we technically have an inconsistency, but for now we just log.
                            eprintln!("Vector store insertion failed for {}: {}", key, e);
                        }
                    }
                }

                if inserted {
                    added += 1;
                }
            }
        }

        Ok((added, 0))
    }

    /// Update access statistics for a memory (URI)
    /// This enables the "human-like" forgetting and reinforcement mechanism.
    pub fn update_access_stats(&self, uri: &str) -> Result<()> {
        let node = NamedNode::new(uri)?;
        let last_accessed = NamedNode::new(EpisodicMemory::PRED_LAST_ACCESSED)?;
        let access_count = NamedNode::new(EpisodicMemory::PRED_ACCESS_COUNT)?;
        let timestamp = Utc::now().to_rfc3339();

        // 1. Update Last Accessed
        // Remove old timestamp if exists
        // We need to find the old quad to delete it
        let old_time_quads: Vec<Quad> = self
            .store
            .quads_for_pattern(
                Some(node.as_ref().into()),
                Some(last_accessed.as_ref()),
                None,
                None,
            )
            .filter_map(Result::ok)
            .collect();

        for q in old_time_quads {
            self.store.remove(&q)?;
        }

        self.store.insert(&Quad::new(
            node.clone(),
            last_accessed,
            Literal::new_simple_literal(&timestamp),
            GraphName::DefaultGraph,
        ))?;

        // 2. Increment Access Count
        let mut count = 0;
        let old_count_quads: Vec<Quad> = self
            .store
            .quads_for_pattern(
                Some(node.as_ref().into()),
                Some(access_count.as_ref()),
                None,
                None,
            )
            .filter_map(Result::ok)
            .collect();

        for q in old_count_quads {
            if let Term::Literal(l) = &q.object {
                if let Ok(c) = l.value().parse::<i32>() {
                    count = c;
                }
            }
            self.store.remove(&q)?;
        }

        count += 1;

        self.store.insert(&Quad::new(
            node.clone(),
            access_count,
            Literal::new_simple_literal(&count.to_string()),
            GraphName::DefaultGraph,
        ))?;

        Ok(())
    }

    /// Calculate activation of a node based on recency and frequency
    /// Activation = (Frequency / (1 + Decay * TimeSinceLastAccess))
    pub fn get_activation(&self, uri: &str) -> f32 {
        let clean_uri = uri.trim_start_matches('<').trim_end_matches('>');
        let node = match NamedNode::new(clean_uri) {
            Ok(n) => n,
            Err(_) => return 0.0,
        };

        let last_accessed_pred =
            match NamedNode::new(EpisodicMemory::PRED_LAST_ACCESSED) {
                Ok(n) => n,
                Err(_) => return 0.0,
            };
        let access_count_pred =
            match NamedNode::new(EpisodicMemory::PRED_ACCESS_COUNT) {
                Ok(n) => n,
                Err(_) => return 0.0,
            };

        let mut frequency = 1.0;
        let mut last_access_time = Utc::now();
        let mut found_stats = false;

        // Get Frequency
        if let Some(q) = self
            .store
            .quads_for_pattern(
                Some(node.as_ref().into()),
                Some(access_count_pred.as_ref()),
                None,
                None,
            )
            .flatten()
            .next()
        {
            if let Term::Literal(l) = q.object {
                if let Ok(c) = l.value().parse::<f32>() {
                    frequency = c;
                    found_stats = true;
                }
            }
        }

        if !found_stats {
            return 0.0;
        }

        // Get Recency
        if let Some(q) = self
            .store
            .quads_for_pattern(
                Some(node.as_ref().into()),
                Some(last_accessed_pred.as_ref()),
                None,
                None,
            )
            .flatten()
            .next()
        {
            if let Term::Literal(l) = q.object {
                if let Ok(t) = chrono::DateTime::parse_from_rfc3339(l.value()) {
                    last_access_time = t.with_timezone(&Utc);
                }
            }
        }

        let hours_since = (Utc::now() - last_access_time).num_minutes() as f32 / 60.0;
        let decay = 0.1; // Decay constant

        // Activation formula
        frequency / (1.0 + decay * hours_since)
    }

    /// Spreading Activation Search
    /// Simulates thought flow: traversing the graph based on connection strength and node activation.
    pub fn spreading_activation_search(
        &self,
        start_uris: Vec<String>,
        steps: u32,
        decay_factor: f32,
    ) -> Result<Vec<(String, f32)>> {
        let mut activation_map: HashMap<String, f32> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();

        // Initial activation
        for uri in start_uris {
            let base_activation = self.get_activation(&uri).max(1.0);
            activation_map.insert(uri, base_activation);
        }

        for _ in 0..steps {
            let mut next_activations = HashMap::new();

            for (uri, current_val) in &activation_map {
                if visited.contains(uri) {
                    continue;
                }
                visited.insert(uri.clone());

                // Find neighbors
                let clean_uri = uri.trim_start_matches('<').trim_end_matches('>');
                let node = match NamedNode::new(clean_uri) {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                let neighbors: Vec<String> = self
                    .store
                    .quads_for_pattern(Some(node.as_ref().into()), None, None, None)
                    .flatten()
                    .map(|q| q.object.to_string())
                    .collect();

                if neighbors.is_empty() {
                    continue;
                }

                // Spread activation to neighbors
                // Distributed evenly? Or copy? Let's dampen it.
                let spread_value = (current_val * decay_factor) / (neighbors.len() as f32).max(1.0);

                for neighbor in neighbors {
                    // Check if neighbor is a Literal, skip if so (usually leaf nodes)
                    if neighbor.starts_with('"') {
                         continue;
                    }

                    // Clean neighbor URI (remove brackets)
                    let clean_neighbor = neighbor.trim_start_matches('<').trim_end_matches('>').to_string();

                    let neighbor_activation = self.get_activation(&clean_neighbor).max(0.1); // Base node strength

                    // New value = spread input + intrinsic strength
                    let new_val = spread_value + neighbor_activation;

                    let entry = next_activations.entry(clean_neighbor).or_insert(0.0);
                    if new_val > *entry {
                        *entry = new_val;
                    }
                }
            }

            // Merge next step into main map
            for (k, v) in next_activations {
                let entry = activation_map.entry(k).or_insert(0.0);
                if v > *entry {
                    *entry = v;
                }
            }
        }

        // Convert to sorted vec
        let mut results: Vec<(String, f32)> = activation_map.into_iter().collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(results)
    }

    /// Hybrid search: vector similarity + graph expansion (or spreading activation)
    pub async fn hybrid_search(
        &self,
        query: &str,
        vector_k: usize,
        graph_depth: u32,
        use_spreading_activation: bool,
        decay_factor: f32,
    ) -> Result<Vec<(String, f32)>> {
        let mut results = Vec::new();

        // Step 1: Vector search
        if let Some(ref vs) = self.vector_store {
            let vector_results = vs.search(query, vector_k).await?;

            for result in vector_results {
                // Use the URI from metadata/result (which maps to Subject URI for triples)
                let uri = result.uri.clone();
                results.push((uri.clone(), result.score));

                // Reinforce memory (simulate "recalling" it)
                let _ = self.update_access_stats(&uri);
            }

            if graph_depth > 0 {
                // Collect top URIs for expansion
                let top_uris: Vec<String> = results.iter().take(5).map(|(u, _)| u.clone()).collect();

                let expanded_results = if use_spreading_activation {
                    self.spreading_activation_search(top_uris, graph_depth, decay_factor)?
                } else {
                    // Legacy expansion
                    let mut exp = Vec::new();
                    for uri in top_uris {
                        let sub_exp = self.expand_graph(&uri, graph_depth)?;
                        for e in sub_exp {
                            exp.push((e, 0.5)); // Arbitrary score
                        }
                    }
                    exp
                };

                // Merge results
                for (uri, score) in expanded_results {
                    results.push((uri, score));
                }
            }
        }

        // Remove duplicates and sort by score
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        results.dedup_by(|a, b| a.0 == b.0);

        Ok(results)
    }

    /// Expand graph from a starting URI
    fn expand_graph(&self, start_uri: &str, depth: u32) -> Result<Vec<String>> {
        let mut expanded = Vec::new();

        if depth == 0 {
            return Ok(expanded);
        }

        // Query for all triples where start_uri is subject or object
        let subject = NamedNodeRef::new(start_uri).ok();

        if let Some(subj) = subject {
            for q in self
                .store
                .quads_for_pattern(Some(subj.into()), None, None, None)
                .flatten()
            {
                expanded.push(q.object.to_string());

                // Recursive expansion (simplified, depth-1)
                if depth > 1 {
                    let nested = self.expand_graph(&q.object.to_string(), depth - 1)?;
                    expanded.extend(nested);
                }
            }
        }

        Ok(expanded)
    }

    pub fn query_sparql(&self, query: &str) -> Result<String> {
        use oxigraph::sparql::QueryResults;

        let results = self.store.query(query)?;

        match results {
            QueryResults::Solutions(solutions) => {
                let mut results_array = Vec::new();
                for solution in solutions {
                    let sol = solution?;
                    let mut mapping = serde_json::Map::new();
                    for (variable, value) in sol.iter() {
                        mapping.insert(
                            variable.to_string(),
                            serde_json::to_value(value.to_string()).unwrap(),
                        );
                    }
                    results_array.push(serde_json::Value::Object(mapping));
                }
                Ok(serde_json::to_string(&results_array)?)
            }
            QueryResults::Boolean(b) => Ok(b.to_string()),
            _ => Ok("[]".to_string()),
        }
    }

    pub fn get_degree(&self, uri: &str) -> usize {
        let node = NamedNodeRef::new(uri).ok();
        if let Some(n) = node {
            let outgoing = self
                .store
                .quads_for_pattern(Some(n.into()), None, None, None)
                .count();
            let incoming = self
                .store
                .quads_for_pattern(None, None, Some(n.into()), None)
                .count();
            outgoing + incoming
        } else {
            0
        }
    }

    pub fn ensure_uri(&self, s: &str) -> String {
        let clean = s.trim_start_matches('<').trim_end_matches('>');
        if clean.starts_with("http") || clean.starts_with("urn:") {
            clean.to_string()
        } else {
            format!("http://synapse.os/{}", clean)
        }
    }
}
