#[cfg(feature = "memory-synapse")]
mod synapse_tests {
    use anyhow::Result;
    use std::sync::Arc;
    use tempfile::TempDir;
    use zeroclaw::agent::synapse::{Orchestrator, SwarmManager};
    use zeroclaw::memory::graph_traits::{
        AgentRole, EdgeDirection, GraphMemory, GraphNodeUpsert, NeighborhoodQuery, NodeId,
        RelationType, SemanticGraphQuery, SemanticSymbolicFilter, SynapseNodeType,
    };
    use zeroclaw::memory::synapse::ontology::{classes, namespaces, properties};
    use zeroclaw::memory::{Memory, SqliteMemory, SynapseMemory};

    #[tokio::test]
    async fn test_synapse_full_flow() -> Result<()> {
        let tmp = TempDir::new()?;
        let workspace = tmp.path();

        // 1. Initialize Memory
        let sqlite = SqliteMemory::new(workspace)?;
        let memory = Arc::new(SynapseMemory::new(workspace, sqlite)?);

        // 2. Register Agent via SwarmManager
        let swarm = SwarmManager::new(memory.clone());
        swarm
            .register_agent("agent_007", "Assistant", vec!["search_tool"])
            .await?;

        // Verify Agent Node exists
        let query = format!(
            "ASK {{ <{}agent_007> a <{}> }}",
            namespaces::ZEROCLAW,
            classes::AGENT
        );
        let result = memory.query_sparql(&query)?;
        assert!(result.contains("true"), "Agent node should exist");

        // 3. Create Task
        let task_id = swarm.create_task("Analyze market trends", 10).await?;
        println!("Created task: {}", task_id);

        // Verify Task Node exists
        let query_task = format!(
            "ASK {{ <{}Task/{}> a <{}> }}",
            namespaces::ZEROCLAW,
            task_id,
            classes::TASK
        );
        let result_task = memory.query_sparql(&query_task)?;
        assert!(result_task.contains("true"), "Task node should exist");

        // 4. Run Orchestrator Cycle (Assign Task)
        let _orchestrator = Orchestrator::new(memory.clone());

        // Simulate Orchestrator Logic: Find unassigned task
        let find_query = format!(
            "SELECT ?task WHERE {{
                ?task a <{}> .
                FILTER NOT EXISTS {{ ?task <{}> ?agent }}
            }}",
            classes::TASK,
            properties::ASSIGNED_TO
        );
        let json = memory.query_sparql(&find_query)?;
        assert!(json.contains(&task_id), "Task should be unassigned");

        // Assign it
        let agent_uri = format!("{}agent_007", namespaces::ZEROCLAW);
        let task_uri = format!("{}Task/{}", namespaces::ZEROCLAW, task_id);
        memory
            .ingest_triples(vec![(
                task_uri.clone(),
                properties::ASSIGNED_TO.to_string(),
                agent_uri.clone(),
            )])
            .await?;

        // 5. Verify Assignment
        let check_assign = format!(
            "ASK {{ <{}> <{}> <{}> }}",
            task_uri,
            properties::ASSIGNED_TO,
            agent_uri
        );
        let assigned = memory.query_sparql(&check_assign)?;
        assert!(assigned.contains("true"), "Task should be assigned");

        // 6. Test Vector Search path
        let content = "The sky is blue and the sun is bright.";
        memory
            .store(
                "fact_1",
                content,
                zeroclaw::memory::MemoryCategory::Core,
                None,
            )
            .await?;

        let _results = memory.recall("weather", 1, None).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_synapse_neighborhood_query_returns_non_empty_edges() -> Result<()> {
        let tmp = TempDir::new()?;
        let workspace = tmp.path();

        let sqlite = SqliteMemory::new(workspace)?;
        let memory = Arc::new(SynapseMemory::new(workspace, sqlite)?);

        memory
            .ingest_triples(vec![(
                format!("{}node-source", namespaces::ZEROCLAW),
                properties::RELATES_TO.to_string(),
                format!("{}node-target", namespaces::ZEROCLAW),
            )])
            .await?;

        let edges = memory
            .query_by_neighborhood(NeighborhoodQuery {
                anchor: NodeId::new("node-source")?,
                direction: EdgeDirection::Outbound,
                relation: Some(RelationType::DecisionConstraint),
            })
            .await?;

        assert!(
            !edges.is_empty(),
            "expected at least one edge for known triple"
        );
        Ok(())
    }
    #[tokio::test]
    async fn test_synapse_semantic_search_returns_score_and_typed_payload() -> Result<()> {
        let tmp = TempDir::new()?;
        let workspace = tmp.path();

        let sqlite = SqliteMemory::new(workspace)?;
        let memory = Arc::new(SynapseMemory::new(workspace, sqlite)?);

        memory
            .upsert_node(GraphNodeUpsert {
                id: NodeId::new("agent-search")?,
                node_type: SynapseNodeType::Agent,
                content: "typed search payload for assistant".to_string(),
                agent_role: Some(AgentRole::Assistant),
                decision_rule_id: None,
            })
            .await?;

        let results = memory
            .semantic_search_with_filters(SemanticGraphQuery {
                text: "typed search payload for assistant".to_string(),
                limit: 3,
                filter: Some(SemanticSymbolicFilter {
                    relation: None,
                    node_type: Some(SynapseNodeType::Agent),
                    agent_role: Some(AgentRole::Assistant),
                    decision_rule_id: None,
                }),
            })
            .await?;

        assert_eq!(results.len(), 1);
        assert!(results[0].score.is_finite());
        assert_eq!(results[0].node.id, NodeId::new("agent-search")?);
        assert_eq!(results[0].node.node_type, SynapseNodeType::Agent);
        assert_eq!(results[0].node.agent_role, Some(AgentRole::Assistant));
        assert_eq!(
            results[0].node.content,
            "typed search payload for assistant"
        );
        Ok(())
    }
}
