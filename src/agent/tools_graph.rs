use crate::memory::Memory;
use crate::tools::Tool;
use anyhow::Result;

#[cfg(feature = "memory-synapse")]
use crate::memory::graph_traits::{GraphNodeUpsert, NodeId, SynapseNodeType};
#[cfg(feature = "memory-synapse")]
use crate::memory::synapse::ontology::{classes, namespaces};

pub async fn register_tools_as_nodes(
    tools: &[Box<dyn Tool>],
    memory: &dyn Memory,
) -> Result<()> {
    #[cfg(feature = "memory-synapse")]
    {
        tracing::info!("🛠️ Registering {} tools as graph nodes", tools.len());

        for tool in tools {
            let tool_name = tool.name();
            let description = tool.description();
            let schema = tool.parameters_schema().to_string();

            // Node ID: Tool/<name>
            let node_id_str = format!("Tool/{}", tool_name);
            let node_id = NodeId::new(&node_id_str)?;

            // Upsert tool node
            // In SynapseMemory::upsert_node, we map SynapseNodeType::Agent to classes::AGENT
            // But tools are more like capabilities or a subtype of Agent.
            // For now, let's treat them as AgentRole::Tool nodes.
            let node = GraphNodeUpsert {
                id: node_id,
                node_type: SynapseNodeType::Agent, // Tools are active agents in the system
                content: description.to_string(),
                agent_role: Some(crate::memory::graph_traits::AgentRole::Tool),
                decision_rule_id: None,
            };

            if let Err(e) = memory.upsert_node(node).await {
                tracing::warn!("Failed to register tool node {}: {}", tool_name, e);
                continue;
            }

            // Add additional metadata via triples (Parameter Schema)
            // This allows the reasoning engine to see *how* to use the tool
            let tool_uri = format!("{}{}", namespaces::ZEROCLAW, node_id_str);

            let schema_triple = (
                tool_uri.clone(),
                format!("{}hasSchema", namespaces::ZEROCLAW),
                format!("\"{}\"", schema.replace("\"", "\\\"")),
            );

            // We can also link the tool to concepts if we parse the description
            // e.g. "shell" -> "execute commands"
            // For V1, we just store the schema.

            if let Err(e) = memory.ingest_triples(vec![schema_triple]).await {
                 tracing::warn!("Failed to add schema triples for tool {}: {}", tool_name, e);
            }
        }
    }

    #[cfg(not(feature = "memory-synapse"))]
    {
        // No-op if feature disabled
        let _ = tools;
        let _ = memory;
        tracing::debug!("Tool graph registration skipped (memory-synapse disabled)");
    }

    Ok(())
}
