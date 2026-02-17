# Graph Memory Hexagonal Boundary

## Intent

The graph-oriented memory capability is modeled as a dedicated port:
`memory::graph_traits::GraphMemory`.

Agent/domain code should depend on this trait (port), not on concrete
`synapse-engine` APIs (adapter implementation detail).

## Port contracts

`GraphMemory` defines the minimum operations required by the domain:

- node upsert (`upsert_node`)
- typed edge upsert (`upsert_typed_edge`)
- neighborhood / relation queries (`query_by_neighborhood`)
- semantic search with symbolic filters (`semantic_search_with_filters`)

## Typing contract

Strong domain types are used instead of untyped strings:

- `NodeId`
- `RelationType`
- `AgentRole`
- `DecisionRuleId`

These ensure domain-level invariants and keep graph semantics explicit.

## Composition strategy

To preserve backward compatibility:

- `Memory` remains unchanged.
- `SynapseMemory` implements both `Memory` and `GraphMemory`.

This allows gradual adoption of graph capabilities without breaking existing
memory backends or integrations.

## Domain adapter

`memory::synapse_domain_adapter::SynapseDomainAdapter` maps
`MemoryCategory` values to graph-level `SynapseNodeType` and relation types,
so existing memory categories can be bridged into Synapse graph semantics
without leaking concrete client details into domain logic.
