use anyhow::Result;
use std::time::Duration;
use tokio::time;
use crate::memory::{Memory, GraphMemory};
use std::sync::Arc;

pub struct DreamingEngine {
    memory: Arc<dyn Memory>,
}

impl DreamingEngine {
    pub fn new(memory: Arc<dyn Memory>) -> Self {
        Self { memory }
    }

    pub async fn run(&self) -> Result<()> {
        let mut interval = time::interval(Duration::from_secs(60 * 60)); // Run every hour

        loop {
            interval.tick().await;
            tracing::info!("💤 Dreaming: Starting memory consolidation cycle...");

            // 1. Detect Contradictions
            if let Err(e) = self.detect_contradictions().await {
                tracing::error!("Dreaming: Failed to detect contradictions: {}", e);
            }

            // 2. Consolidate Memory (Prune Drafts)
            if let Err(e) = self.consolidate_memory().await {
                tracing::error!("Dreaming: Failed to consolidate memory: {}", e);
            }

            tracing::info!("💤 Dreaming cycle complete.");
        }
    }

    async fn detect_contradictions(&self) -> Result<()> {
        // Detect if any subject has multiple values for functional properties (properties that should be unique)
        // e.g. birthDate, bloodType, etc.
        // We look for patterns where ?s ?p ?o1 AND ?s ?p ?o2 AND ?o1 != ?o2
        // AND ?p is marked as FunctionalProperty in ontology

        let query = "SELECT ?s ?p ?o1 ?o2 WHERE { \
                 ?p <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://www.w3.org/2002/07/owl#FunctionalProperty> . \
                 ?s ?p ?o1 . \
                 ?s ?p ?o2 . \
                 FILTER (?o1 != ?o2) \
             } LIMIT 100";

        let result_json = self.memory.query_sparql(query).await?;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&result_json)?;

        if !rows.is_empty() {
            tracing::warn!("Dreaming: Found {} contradictions in functional properties", rows.len());
            // In V1, we log them. In V2, we might create a "ConflictResolution" task for the agent.
            for row in rows {
                tracing::warn!("  Conflict: Subject {:?} has multiple values for {:?}", row.get("s"), row.get("p"));
            }
        }

        Ok(())
    }

    async fn consolidate_memory(&self) -> Result<()> {
        // Garbage Collection: Remove nodes marked as 'Draft' older than 24 hours
        // This keeps the graph clean from temporary thought bubbles

        let query = "DELETE { ?s ?p ?o . } WHERE { \
                 ?s <http://zeroclaw.ai/schema#status> \"Draft\" . \
                 ?s <http://zeroclaw.ai/schema#createdAt> ?date . \
                 ?s ?p ?o . \
                 BIND(NOW() - \"P1D\"^^<http://www.w3.org/2001/XMLSchema#duration> AS ?threshold) \
                 FILTER (?date < ?threshold) \
             }";

        // Note: DELETE/INSERT support depends on the backend's SPARQL Update capability.
        // Synapse/Oxigraph supports SPARQL 1.1 Update.
        let result = self.memory.query_sparql(query).await?;

        // Since query_sparql returns JSON result for SELECT, or a simple "OK" / count for UPDATE
        // We log the output for debugging.
        tracing::debug!("Dreaming: Consolidation result: {}", result);

        Ok(())
    }
}
