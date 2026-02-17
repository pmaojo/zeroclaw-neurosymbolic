use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SwarmAgentId(String);

impl SwarmAgentId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_string();
        if value.is_empty() {
            bail!("swarm agent id cannot be empty");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CapabilityTag(String);

impl CapabilityTag {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_ascii_lowercase();
        if value.is_empty() {
            bail!("capability tag cannot be empty");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportingEdge {
    pub agent: SwarmAgentId,
    pub reports_to: SwarmAgentId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskIntent {
    pub problem_statement: String,
    pub required_capabilities: Vec<CapabilityTag>,
}

impl TaskIntent {
    pub fn new(
        problem_statement: impl Into<String>,
        required_capabilities: Vec<CapabilityTag>,
    ) -> Result<Self> {
        let problem_statement = problem_statement.into().trim().to_string();
        if problem_statement.is_empty() {
            bail!("task intent requires a non-empty problem statement");
        }
        Ok(Self {
            problem_statement,
            required_capabilities,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedContext {
    pub content: String,
}

impl SharedContext {
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SwarmGuardrails {
    pub max_team_iterations: usize,
    pub max_agent_invocations: usize,
    pub max_shared_context_chars: usize,
}

impl Default for SwarmGuardrails {
    fn default() -> Self {
        Self {
            max_team_iterations: 16,
            max_agent_invocations: 4,
            max_shared_context_chars: 8_000,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SwarmGraph {
    expertise: HashMap<SwarmAgentId, HashSet<CapabilityTag>>,
    reporting: Vec<ReportingEdge>,
}

impl SwarmGraph {
    pub fn add_expertise(&mut self, agent: SwarmAgentId, capability: CapabilityTag) {
        self.expertise.entry(agent).or_default().insert(capability);
    }

    pub fn add_reporting_edge(&mut self, edge: ReportingEdge) {
        self.reporting.push(edge);
    }

    fn experts_for(&self, capability: &CapabilityTag) -> Vec<SwarmAgentId> {
        self.expertise
            .iter()
            .filter_map(|(agent, capabilities)| {
                if capabilities.contains(capability) {
                    Some(agent.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn managers_for(&self, agent: &SwarmAgentId) -> Vec<SwarmAgentId> {
        self.reporting
            .iter()
            .filter_map(|edge| {
                if &edge.agent == agent {
                    Some(edge.reports_to.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingDecision {
    pub selected_agents: Vec<SwarmAgentId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInvocation {
    pub agent_id: SwarmAgentId,
    pub output: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinationResult {
    pub decision: RoutingDecision,
    pub invocations: Vec<AgentInvocation>,
}

#[async_trait]
pub trait AgentTurnExecutor: Send + Sync {
    async fn run_agent_turn(
        &self,
        agent_id: &SwarmAgentId,
        task_intent: &TaskIntent,
        shared_context: &SharedContext,
    ) -> Result<String>;
}

pub struct SwarmCoordinator {
    graph: SwarmGraph,
    guardrails: SwarmGuardrails,
}

impl SwarmCoordinator {
    pub fn new(graph: SwarmGraph, guardrails: SwarmGuardrails) -> Self {
        Self { graph, guardrails }
    }

    pub fn route_agents(&self, task_intent: &TaskIntent) -> Result<RoutingDecision> {
        let mut queue = VecDeque::new();
        let mut selected = Vec::new();
        let mut seen = HashSet::new();

        for capability in &task_intent.required_capabilities {
            for agent in self.graph.experts_for(capability) {
                queue.push_back(agent);
            }
        }

        let mut team_iterations = 0usize;

        while let Some(agent) = queue.pop_front() {
            team_iterations += 1;
            if team_iterations > self.guardrails.max_team_iterations {
                bail!(
                    "swarm routing exceeded team iteration guardrail ({})",
                    self.guardrails.max_team_iterations
                );
            }

            if !seen.insert(agent.clone()) {
                continue;
            }

            selected.push(agent.clone());

            for manager in self.graph.managers_for(&agent) {
                queue.push_back(manager);
            }
        }

        Ok(RoutingDecision {
            selected_agents: selected,
        })
    }

    pub async fn coordinate<E: AgentTurnExecutor>(
        &self,
        task_intent: &TaskIntent,
        shared_context: SharedContext,
        executor: &E,
    ) -> Result<CoordinationResult> {
        if shared_context.content.chars().count() > self.guardrails.max_shared_context_chars {
            bail!(
                "shared context exceeds guardrail ({} chars)",
                self.guardrails.max_shared_context_chars
            );
        }

        let decision = self.route_agents(task_intent)?;
        let mut invocations = Vec::with_capacity(decision.selected_agents.len());
        let mut invocation_count: HashMap<&SwarmAgentId, usize> = HashMap::new();

        for agent_id in &decision.selected_agents {
            let count = invocation_count.entry(agent_id).or_insert(0);
            *count += 1;
            if *count > self.guardrails.max_agent_invocations {
                bail!(
                    "agent '{}' exceeded per-agent invocation guardrail ({})",
                    agent_id.as_str(),
                    self.guardrails.max_agent_invocations
                );
            }

            let output = executor
                .run_agent_turn(agent_id, task_intent, &shared_context)
                .await?;
            invocations.push(AgentInvocation {
                agent_id: agent_id.clone(),
                output,
            });
        }

        Ok(CoordinationResult {
            decision,
            invocations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str) -> SwarmAgentId {
        SwarmAgentId::new(id).unwrap()
    }

    fn capability(tag: &str) -> CapabilityTag {
        CapabilityTag::new(tag).unwrap()
    }

    struct FakeExecutor;

    #[async_trait]
    impl AgentTurnExecutor for FakeExecutor {
        async fn run_agent_turn(
            &self,
            agent_id: &SwarmAgentId,
            task_intent: &TaskIntent,
            _shared_context: &SharedContext,
        ) -> Result<String> {
            Ok(format!(
                "{} handled {}",
                agent_id.as_str(),
                task_intent.problem_statement
            ))
        }
    }

    #[test]
    fn route_agents_selects_experts_and_reporting_chain() {
        let mut graph = SwarmGraph::default();
        graph.add_expertise(agent("agent_a"), capability("rust"));
        graph.add_reporting_edge(ReportingEdge {
            agent: agent("agent_a"),
            reports_to: agent("lead_a"),
        });

        let coordinator = SwarmCoordinator::new(
            graph,
            SwarmGuardrails {
                max_team_iterations: 8,
                ..SwarmGuardrails::default()
            },
        );

        let intent = TaskIntent::new("Fix compile issue", vec![capability("rust")]).unwrap();
        let routing = coordinator.route_agents(&intent).unwrap();

        assert_eq!(
            routing.selected_agents,
            vec![agent("agent_a"), agent("lead_a")]
        );
    }

    #[test]
    fn route_agents_deduplicates_agents_across_capabilities() {
        let shared_agent = agent("agent_shared");
        let mut graph = SwarmGraph::default();
        graph.add_expertise(shared_agent.clone(), capability("rust"));
        graph.add_expertise(shared_agent.clone(), capability("security"));

        let coordinator = SwarmCoordinator::new(graph, SwarmGuardrails::default());

        let intent = TaskIntent::new(
            "Audit runtime",
            vec![capability("rust"), capability("security")],
        )
        .unwrap();

        let routing = coordinator.route_agents(&intent).unwrap();
        assert_eq!(routing.selected_agents, vec![shared_agent]);
    }

    #[tokio::test]
    async fn coordinate_runs_atomic_turn_per_selected_agent() {
        let mut graph = SwarmGraph::default();
        graph.add_expertise(agent("agent_rust"), capability("rust"));

        let coordinator = SwarmCoordinator::new(graph, SwarmGuardrails::default());
        let intent = TaskIntent::new("Implement module", vec![capability("rust")]).unwrap();

        let result = coordinator
            .coordinate(&intent, SharedContext::new("shared plan"), &FakeExecutor)
            .await
            .unwrap();

        assert_eq!(result.invocations.len(), 1);
        assert_eq!(result.invocations[0].agent_id, agent("agent_rust"));
        assert!(result.invocations[0].output.contains("Implement module"));
    }

    #[test]
    fn route_agents_fails_when_team_iteration_guardrail_is_exceeded() {
        let mut graph = SwarmGraph::default();
        graph.add_expertise(agent("agent_a"), capability("rust"));
        graph.add_reporting_edge(ReportingEdge {
            agent: agent("agent_a"),
            reports_to: agent("lead_a"),
        });
        graph.add_reporting_edge(ReportingEdge {
            agent: agent("lead_a"),
            reports_to: agent("director_a"),
        });

        let coordinator = SwarmCoordinator::new(
            graph,
            SwarmGuardrails {
                max_team_iterations: 1,
                ..SwarmGuardrails::default()
            },
        );

        let intent = TaskIntent::new("Fix compile issue", vec![capability("rust")]).unwrap();
        let error = coordinator.route_agents(&intent).unwrap_err().to_string();
        assert!(error.contains("team iteration guardrail"));
    }

    #[tokio::test]
    async fn coordinate_fails_when_shared_context_limit_is_exceeded() {
        let mut graph = SwarmGraph::default();
        graph.add_expertise(agent("agent_rust"), capability("rust"));

        let coordinator = SwarmCoordinator::new(
            graph,
            SwarmGuardrails {
                max_shared_context_chars: 4,
                ..SwarmGuardrails::default()
            },
        );

        let intent = TaskIntent::new("Implement module", vec![capability("rust")]).unwrap();
        let error = coordinator
            .coordinate(&intent, SharedContext::new("too long"), &FakeExecutor)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("shared context exceeds guardrail"));
    }
}
