use super::graph_traits::{RelationType, SynapseNodeType};
use super::traits::MemoryCategory;

/// Adapter between current memory categories and Synapse graph domain types.
///
/// Hexagonal boundary: agent/domain code depends on graph contracts and this
/// adapter, never on concrete synapse-engine client APIs.
pub struct SynapseDomainAdapter;

impl SynapseDomainAdapter {
    pub fn category_to_node_type(category: &MemoryCategory) -> SynapseNodeType {
        match category {
            MemoryCategory::Core => SynapseNodeType::MemoryCore,
            MemoryCategory::Daily => SynapseNodeType::MemoryDaily,
            MemoryCategory::Conversation => SynapseNodeType::MemoryConversation,
            MemoryCategory::Custom(_) => SynapseNodeType::MemoryCustom,
        }
    }

    pub fn category_to_relation_type(_category: &MemoryCategory) -> RelationType {
        RelationType::MessageLink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_maps_builtin_categories_to_synapse_node_types() {
        assert_eq!(
            SynapseDomainAdapter::category_to_node_type(&MemoryCategory::Core),
            SynapseNodeType::MemoryCore
        );
        assert_eq!(
            SynapseDomainAdapter::category_to_node_type(&MemoryCategory::Daily),
            SynapseNodeType::MemoryDaily
        );
        assert_eq!(
            SynapseDomainAdapter::category_to_node_type(&MemoryCategory::Conversation),
            SynapseNodeType::MemoryConversation
        );
    }

    #[test]
    fn adapter_maps_custom_category_to_memory_custom_type() {
        assert_eq!(
            SynapseDomainAdapter::category_to_node_type(&MemoryCategory::Custom("x".into())),
            SynapseNodeType::MemoryCustom
        );
    }

    #[test]
    fn adapter_uses_message_link_relation() {
        let relation =
            SynapseDomainAdapter::category_to_relation_type(&MemoryCategory::Custom("x".into()));
        assert_eq!(relation, RelationType::MessageLink);
    }
}
