use anyhow::Result;
use serde_json::Value;
#[cfg(feature = "memory-synapse")]
use crate::memory::SynapseMemory;
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, properties, namespaces, task_status};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub struct Orchestrator {
    #[cfg(feature = "memory-synapse")]
    memory: Arc<SynapseMemory>,
    #[cfg(not(feature = "memory-synapse"))]
    _marker: std::marker::PhantomData<()>,
}

impl Orchestrator {
    #[cfg(feature = "memory-synapse")]
    pub fn new(memory: Arc<SynapseMemory>) -> Self {
        Self { memory }
    }

    #[cfg(not(feature = "memory-synapse"))]
    pub fn new() -> Self {
        Self { _marker: std::marker::PhantomData }
    }

    /// Run the main orchestration loop
    /// This runs forever, checking for unassigned tasks and matching them to agents.
    #[allow(unused_variables)]
    pub async fn run(&self) -> Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            info!("Starting Synapse Orchestrator Loop...");
            loop {
                if let Err(e) = self.cycle().await {
                    warn!("Orchestrator cycle failed: {}", e);
                }
                sleep(Duration::from_secs(5)).await;
            }
        }
        #[cfg(not(feature = "memory-synapse"))]
        {
            warn!("Synapse Orchestrator disabled (feature 'memory-synapse' missing)");
            Ok(())
        }
    }

    #[cfg(feature = "memory-synapse")]
    async fn cycle(&self) -> Result<()> {
        // 1. Find unassigned pending tasks
        let tasks = self.find_unassigned_tasks().await?;

        for task in tasks {
            // 2. Find best agent for task
            if let Some(agent_uri) = self.find_agent_for_task(&task).await? {
                // 3. Assign task
                self.assign_task(&task, &agent_uri).await?;
                info!("Assigned task {} to agent {}", task, agent_uri);
            } else {
                warn!("No suitable agent found for task {}", task);
            }
        }

        Ok(())
    }

    #[cfg(feature = "memory-synapse")]
    async fn find_unassigned_tasks(&self) -> Result<Vec<String>> {
        let query = format!(
            "SELECT ?task WHERE {{
                ?task <{rdf_type}> <{task_class}> .
                ?task <{has_status}> <{pending}> .
                FILTER NOT EXISTS {{ ?task <{assigned_to}> ?agent }}
            }}",
            rdf_type = namespaces::RDF.to_owned() + "type",
            task_class = classes::TASK,
            has_status = properties::HAS_STATUS,
            pending = task_status::PENDING,
            assigned_to = properties::ASSIGNED_TO
        );

        let json_result = self.memory.query_sparql(&query)?;
        let results: Vec<Value> = serde_json::from_str(&json_result)?;

        let mut tasks = Vec::new();
        for row in results {
            if let Some(uri) = row.get("task").and_then(|v| v.as_str()) {
                tasks.push(uri.to_string());
            }
        }
        Ok(tasks)
    }

    #[cfg(feature = "memory-synapse")]
    async fn find_agent_for_task(&self, _task_uri: &str) -> Result<Option<String>> {
        // Basic logic: Find any agent with "Assistant" role or specific skill match
        // Ideally we query task requirements vs agent skills

        // Let's just pick *any* available agent for now as a fallback
        let query = format!(
            "SELECT ?agent WHERE {{
                ?agent <{rdf_type}> <{agent_class}> .
            }} LIMIT 1",
            rdf_type = namespaces::RDF.to_owned() + "type",
            agent_class = classes::AGENT
        );

        let json_result = self.memory.query_sparql(&query)?;
        let results: Vec<Value> = serde_json::from_str(&json_result)?;

        if let Some(row) = results.first() {
            if let Some(uri) = row.get("agent").and_then(|v| v.as_str()) {
                return Ok(Some(uri.to_string()));
            }
        }

        Ok(None)
    }

    #[cfg(feature = "memory-synapse")]
    async fn assign_task(&self, task_uri: &str, agent_uri: &str) -> Result<()> {
        let triple = (task_uri.to_string(), properties::ASSIGNED_TO.to_string(), agent_uri.to_string());
        self.memory.ingest_triples(vec![triple]).await?;
        Ok(())
    }
}
