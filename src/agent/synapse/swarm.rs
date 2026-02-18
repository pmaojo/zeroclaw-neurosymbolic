#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, namespaces, properties, task_status};
#[cfg(feature = "memory-synapse")]
use crate::memory::SynapseMemory;
use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

pub struct SwarmManager {
    #[cfg(feature = "memory-synapse")]
    memory: std::sync::Arc<SynapseMemory>,
    #[cfg(not(feature = "memory-synapse"))]
    _marker: std::marker::PhantomData<()>,
}

impl SwarmManager {
    #[cfg(feature = "memory-synapse")]
    pub fn new(memory: std::sync::Arc<SynapseMemory>) -> Self {
        Self { memory }
    }

    #[cfg(not(feature = "memory-synapse"))]
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    /// Heartbeat: Check for pending tasks for this agent
    #[allow(unused_variables)]
    pub async fn get_pending_tasks(&self, agent_id: &str) -> Result<Vec<Value>> {
        #[cfg(feature = "memory-synapse")]
        {
            let agent_uri = format!("{}{}", namespaces::ZEROCLAW, agent_id);
            let query = format!(
                "SELECT ?task ?content ?priority WHERE {{
                    ?task <{assigned_to}> <{agent}> .
                    ?task <{has_status}> <{pending}> .
                    ?task <{has_content}> ?content .
                    OPTIONAL {{ ?task <{has_priority}> ?priority }}
                }} ORDER BY DESC(?priority)",
                assigned_to = properties::ASSIGNED_TO,
                agent = agent_uri,
                has_status = properties::HAS_STATUS,
                pending = task_status::PENDING,
                has_content = properties::HAS_CONTENT,
                has_priority = properties::HAS_PRIORITY
            );

            let json_result = self.memory.query_sparql(&query)?;
            let parsed: Vec<Value> = serde_json::from_str(&json_result)?;
            Ok(parsed)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok(vec![])
    }

    /// Create a new Task in the Swarm Graph
    #[allow(unused_variables)]
    pub async fn create_task(&self, description: &str, priority: i32) -> Result<String> {
        #[cfg(feature = "memory-synapse")]
        {
            let task_id = Uuid::new_v4().to_string();
            let task_uri = format!("{}Task/{}", namespaces::ZEROCLAW, task_id);

            let triples = vec![
                (
                    task_uri.clone(),
                    namespaces::RDF.to_owned() + "type",
                    classes::TASK.to_string(),
                ),
                (
                    task_uri.clone(),
                    properties::HAS_CONTENT.to_string(),
                    format!("\"{}\"", description.replace("\"", "\\\"")),
                ),
                (
                    task_uri.clone(),
                    properties::HAS_STATUS.to_string(),
                    task_status::PENDING.to_string(),
                ),
                (
                    task_uri.clone(),
                    properties::HAS_PRIORITY.to_string(),
                    format!(
                        "\"{}\"^^<{}>",
                        priority,
                        namespaces::XSD.to_owned() + "integer"
                    ),
                ),
                (
                    task_uri.clone(),
                    properties::CREATED_AT.to_string(),
                    format!("\"{}\"", chrono::Utc::now().to_rfc3339()),
                ),
            ];

            self.memory.ingest_triples(triples).await?;
            Ok(task_id)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok("mock-task-id".to_string())
    }

    /// Auto-Discovery: Register agent capabilities
    #[allow(unused_variables)]
    pub async fn register_agent(&self, agent_id: &str, role: &str, tools: Vec<&str>) -> Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let agent_uri = format!("{}{}", namespaces::ZEROCLAW, agent_id);
            let mut triples = vec![
                (
                    agent_uri.clone(),
                    namespaces::RDF.to_owned() + "type",
                    classes::AGENT.to_string(),
                ),
                (
                    agent_uri.clone(),
                    properties::HAS_ROLE.to_string(),
                    format!("\"{}\"", role),
                ),
            ];

            for tool in tools {
                let tool_uri = format!("{}Tool/{}", namespaces::ZEROCLAW, tool);
                triples.push((
                    agent_uri.clone(),
                    properties::HAS_TOOL.to_string(),
                    tool_uri.clone(),
                ));
                triples.push((
                    tool_uri,
                    namespaces::RDF.to_owned() + "type",
                    classes::TOOL.to_string(),
                ));
            }

            self.memory.ingest_triples(triples).await?;
        }
        Ok(())
    }

    /// Build System Prompt from Graph Context
    #[allow(unused_variables)]
    pub async fn build_system_context(&self, agent_id: &str) -> Result<String> {
        #[cfg(feature = "memory-synapse")]
        {
            let agent_uri = format!("{}{}", namespaces::ZEROCLAW, agent_id);

            // 1. Fetch Role
            // 2. Fetch Tools
            // 3. Fetch Active Task Context

            let query = format!(
                "SELECT ?role ?tool WHERE {{
                    <{agent}> <{has_role}> ?role .
                    OPTIONAL {{ <{agent}> <{has_tool}> ?tool }}
                }}",
                agent = agent_uri,
                has_role = properties::HAS_ROLE,
                has_tool = properties::HAS_TOOL
            );

            let json_result = self.memory.query_sparql(&query)?;
            let results: Vec<Value> = serde_json::from_str(&json_result)?;

            let mut role = "Assistant".to_string();
            let mut tools = Vec::new();

            for row in results {
                if let Some(r) = row.get("role").and_then(|v| v.as_str()) {
                    role = r.to_string();
                }
                if let Some(t) = row.get("tool").and_then(|v| v.as_str()) {
                    tools.push(t.replace(namespaces::ZEROCLAW, "").replace("Tool/", ""));
                }
            }

            let mut prompt = format!("You are an autonomous agent with the role: {}.\n", role);
            if !tools.is_empty() {
                prompt.push_str("You have access to the following tools defined in the graph:\n");
                for tool in tools {
                    prompt.push_str(&format!("- {}\n", tool));
                }
            }

            prompt.push_str("\nYour decisions update the global state graph.");
            Ok(prompt)
        }
        #[cfg(not(feature = "memory-synapse"))]
        Ok("Standard ZeroClaw System Prompt".into())
    }
}
