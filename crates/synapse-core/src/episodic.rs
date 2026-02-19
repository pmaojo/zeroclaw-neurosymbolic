use anyhow::Result;
use oxigraph::model::{NamedNode, Quad, Term, Literal, GraphName};
use oxigraph::store::Store;
use uuid::Uuid;
use chrono::Utc;

pub struct EpisodicMemory;

impl EpisodicMemory {
    pub const TYPE_EPISODE: &'static str = "http://synapse.os/ontology#Episode";
    pub const PRED_NEXT_EPISODE: &'static str = "http://synapse.os/ontology#nextEpisode";
    pub const PRED_PREV_EPISODE: &'static str = "http://synapse.os/ontology#previousEpisode";
    pub const PRED_HAS_PART: &'static str = "http://synapse.os/ontology#hasPart";
    pub const PRED_TIMESTAMP: &'static str = "http://synapse.os/ontology#timestamp";
    pub const PRED_CONTENT: &'static str = "http://synapse.os/ontology#content";

    // Memory stats
    pub const PRED_LAST_ACCESSED: &'static str = "http://synapse.os/ontology#lastAccessed";
    pub const PRED_ACCESS_COUNT: &'static str = "http://synapse.os/ontology#accessCount";

    pub fn create_episode(store: &Store, content: &str, related_uris: Vec<String>) -> Result<String> {
        let episode_id = Uuid::new_v4();
        let episode_uri = format!("http://synapse.os/episode/{}", episode_id);
        let episode_node = NamedNode::new(&episode_uri)?;

        let type_pred = NamedNode::new("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")?;
        let episode_class = NamedNode::new(Self::TYPE_EPISODE)?;

        let content_pred = NamedNode::new(Self::PRED_CONTENT)?;
        let timestamp_pred = NamedNode::new(Self::PRED_TIMESTAMP)?;
        let has_part_pred = NamedNode::new(Self::PRED_HAS_PART)?;

        let timestamp = Utc::now().to_rfc3339();

        // 1. Define Episode Type
        store.insert(&Quad::new(
            episode_node.clone(),
            type_pred,
            episode_class,
            GraphName::DefaultGraph,
        ))?;

        // 2. Add Content
        store.insert(&Quad::new(
            episode_node.clone(),
            content_pred,
            Literal::new_simple_literal(content),
            GraphName::DefaultGraph,
        ))?;

        // 3. Add Timestamp
        store.insert(&Quad::new(
            episode_node.clone(),
            timestamp_pred,
            Literal::new_simple_literal(&timestamp),
            GraphName::DefaultGraph,
        ))?;

        // 4. Link related entities (subjects of the memory)
        for uri in related_uris {
            if let Ok(node) = NamedNode::new(&uri) {
                store.insert(&Quad::new(
                    episode_node.clone(),
                    has_part_pred.clone(),
                    node,
                    GraphName::DefaultGraph,
                ))?;
            }
        }

        // 5. Initialize Memory Stats (start fresh)
        let last_accessed = NamedNode::new(Self::PRED_LAST_ACCESSED)?;
        let access_count = NamedNode::new(Self::PRED_ACCESS_COUNT)?;

        store.insert(&Quad::new(
            episode_node.clone(),
            last_accessed,
            Literal::new_simple_literal(&timestamp),
            GraphName::DefaultGraph,
        ))?;

        store.insert(&Quad::new(
            episode_node.clone(),
            access_count,
            Literal::new_simple_literal("1"),
            GraphName::DefaultGraph,
        ))?;

        Ok(episode_uri)
    }

    /// Links two episodes chronologically
    pub fn link_episodes(store: &Store, prev_uri: &str, next_uri: &str) -> Result<()> {
        let prev = NamedNode::new(prev_uri)?;
        let next = NamedNode::new(next_uri)?;

        let next_pred = NamedNode::new(Self::PRED_NEXT_EPISODE)?;
        let prev_pred = NamedNode::new(Self::PRED_PREV_EPISODE)?;

        store.insert(&Quad::new(
            prev.clone(),
            next_pred,
            next.clone(),
            GraphName::DefaultGraph,
        ))?;

        store.insert(&Quad::new(
            next,
            prev_pred,
            prev,
            GraphName::DefaultGraph,
        ))?;

        Ok(())
    }
}
