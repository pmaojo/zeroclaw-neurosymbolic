use oxigraph::model::NamedNodeRef;

pub mod namespaces {
    pub const ZEROCLAW: &str = "http://zeroclaw.ai/schema#";
    pub const AGENTS: &str = "http://zeroclaw.ai/agents#";
    pub const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
    pub const RDFS: &str = "http://www.w3.org/2000/01/rdf-schema#";
    pub const OWL: &str = "http://www.w3.org/2002/07/owl#";
    pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";
}

pub mod classes {
    use super::namespaces::ZEROCLAW;

    pub const AGENT: &str = concat!("http://zeroclaw.ai/schema#", "Agent");
    pub const TASK: &str = concat!("http://zeroclaw.ai/schema#", "Task");
    pub const TOOL: &str = concat!("http://zeroclaw.ai/schema#", "Tool");
    pub const MEMORY: &str = concat!("http://zeroclaw.ai/schema#", "Memory");
    pub const SKILL: &str = concat!("http://zeroclaw.ai/schema#", "Skill");
    pub const DECISION_RULE: &str = concat!("http://zeroclaw.ai/schema#", "DecisionRule");
    pub const CONVERSATION: &str = concat!("http://zeroclaw.ai/schema#", "Conversation");
    pub const SCENARIO: &str = concat!("http://zeroclaw.ai/schema#", "Scenario");
}

pub mod properties {
    use super::namespaces::ZEROCLAW;

    // Task Management
    pub const ASSIGNED_TO: &str = concat!("http://zeroclaw.ai/schema#", "assignedTo");
    pub const HAS_STATUS: &str = concat!("http://zeroclaw.ai/schema#", "hasStatus");
    pub const HAS_PRIORITY: &str = concat!("http://zeroclaw.ai/schema#", "hasPriority");
    pub const CREATED_AT: &str = concat!("http://zeroclaw.ai/schema#", "createdAt");
    pub const DUE_BY: &str = concat!("http://zeroclaw.ai/schema#", "dueBy");

    // Agent Capabilities
    pub const HAS_TOOL: &str = concat!("http://zeroclaw.ai/schema#", "hasTool");
    pub const HAS_ROLE: &str = concat!("http://zeroclaw.ai/schema#", "hasRole"); // user, assistant, system
    pub const HAS_SKILL: &str = concat!("http://zeroclaw.ai/schema#", "hasSkill");

    // Knowledge/Memory
    pub const RELATES_TO: &str = concat!("http://zeroclaw.ai/schema#", "relatesTo");
    pub const GENERATED_BY: &str = concat!("http://zeroclaw.ai/schema#", "generatedBy");
    pub const CONTEXT_FOR: &str = concat!("http://zeroclaw.ai/schema#", "contextFor");
    pub const HAS_CONTENT: &str = concat!("http://zeroclaw.ai/schema#", "hasContent");

    // Scenarios
    pub const ACTIVE_SCENARIO: &str = concat!("http://zeroclaw.ai/schema#", "activeScenario");
}

pub mod task_status {
    use super::namespaces::ZEROCLAW;

    pub const PENDING: &str = concat!("http://zeroclaw.ai/schema#", "Pending");
    pub const IN_PROGRESS: &str = concat!("http://zeroclaw.ai/schema#", "InProgress");
    pub const COMPLETED: &str = concat!("http://zeroclaw.ai/schema#", "Completed");
    pub const FAILED: &str = concat!("http://zeroclaw.ai/schema#", "Failed");
}
