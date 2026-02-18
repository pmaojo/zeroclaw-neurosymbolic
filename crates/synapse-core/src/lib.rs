pub mod audit;
pub mod auth;
pub mod disambiguation;
pub mod ingest;
// pub mod mcp_stdio; // Depends on server/protos likely
// pub mod mcp_types;
pub mod persistence;
pub mod processor;
pub mod reasoner;
pub mod scenarios;
// pub mod server; // Disabled: gRPC server not needed for library integration
pub mod store;
pub mod vector_store;
