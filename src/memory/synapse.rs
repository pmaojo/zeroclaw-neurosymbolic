use super::sqlite::SqliteMemory;
use super::traits::{Memory, MemoryCategory, MemoryEntry};
use async_trait::async_trait;
use std::path::Path;

pub struct SynapseMemory {
    local: SqliteMemory,
}

impl SynapseMemory {
    pub fn new(workspace_dir: &Path, local: SqliteMemory) -> anyhow::Result<Self> {
        Self::initialize(workspace_dir)?;
        Ok(Self { local })
    }

    fn initialize(workspace_dir: &Path) -> anyhow::Result<()> {
        #[cfg(feature = "memory-synapse")]
        {
            let _synapse_marker = std::any::TypeId::of::<synapse_engine::Engine>();
            let _workspace_dir = workspace_dir;
            if std::env::var_os("ZEROCLAW_FORCE_SYNAPSE_INIT_ERROR").is_some() {
                anyhow::bail!("forced synapse initialization error");
            }
            return Ok(());
        }

        #[cfg(not(feature = "memory-synapse"))]
        {
            let _workspace_dir = workspace_dir;
            anyhow::bail!(
                "memory backend 'synapse' requires feature 'memory-synapse'; using sqlite fallback"
            );
        }
    }
}

#[async_trait]
impl Memory for SynapseMemory {
    fn name(&self) -> &str {
        "synapse"
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        self.local.store(key, content, category, session_id).await
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.local.recall(query, limit, session_id).await
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<MemoryEntry>> {
        self.local.get(key).await
    }

    async fn list(
        &self,
        category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.local.list(category, session_id).await
    }

    async fn forget(&self, key: &str) -> anyhow::Result<bool> {
        self.local.forget(key).await
    }

    async fn count(&self) -> anyhow::Result<usize> {
        self.local.count().await
    }

    async fn health_check(&self) -> bool {
        self.local.health_check().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[cfg(feature = "memory-synapse")]
    fn synapse_memory_initializes_when_feature_enabled() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let memory = SynapseMemory::new(tmp.path(), sqlite).unwrap();
        assert_eq!(memory.name(), "synapse");
    }

    #[test]
    #[cfg(not(feature = "memory-synapse"))]
    fn synapse_memory_requires_feature_flag() {
        let tmp = TempDir::new().unwrap();
        let sqlite = SqliteMemory::new(tmp.path()).unwrap();
        let result = SynapseMemory::new(tmp.path(), sqlite);
        assert!(result.is_err());
        let error = result.err().unwrap();
        assert!(error
            .to_string()
            .contains("requires feature 'memory-synapse'"));
    }
}
