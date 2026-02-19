use crate::vector_store::{Embedder, SearchResult, VectorStore, create_default_embedder};
use anyhow::{Result, Context};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "lance-storage")]
use lance::dataset::{Dataset, WriteParams, WriteMode};
#[cfg(feature = "lance-storage")]
use arrow_array::{RecordBatch, StringArray, Float32Array, FixedSizeListArray, RecordBatchIterator};
#[cfg(feature = "lance-storage")]
use arrow_schema::{Schema, Field, DataType};
#[cfg(feature = "lance-storage")]
use futures::StreamExt;

#[cfg(feature = "lance-storage")]
pub struct LanceVectorStore {
    path: String,
    embedder: Arc<dyn Embedder>,
}

#[cfg(feature = "lance-storage")]
impl LanceVectorStore {
    pub fn new(namespace: &str, storage_path_root: &str) -> Result<Self> {
        let embedder = create_default_embedder()?;
        Self::new_with_embedder(namespace, storage_path_root, embedder)
    }

    pub fn new_with_embedder(namespace: &str, storage_path_root: &str, embedder: Arc<dyn Embedder>) -> Result<Self> {
        let path = std::path::Path::new(storage_path_root).join(namespace).join("vectors.lance");
        let path_str = path.to_string_lossy().to_string();

        Ok(Self {
            path: path_str,
            embedder,
        })
    }

    async fn get_dataset(&self) -> Result<Dataset> {
        Dataset::open(&self.path).await.map_err(|e| anyhow::anyhow!("Failed to open lance dataset at {}: {}", self.path, e))
    }
}

#[cfg(feature = "lance-storage")]
#[async_trait]
impl VectorStore for LanceVectorStore {
    async fn add(&self, key: &str, content: &str, metadata: serde_json::Value) -> Result<usize> {
        let results = self.add_batch(vec![(key.to_string(), content.to_string(), metadata)]).await?;
        Ok(results[0])
    }

    async fn add_batch(&self, items: Vec<(String, String, serde_json::Value)>) -> Result<Vec<usize>> {
        if items.is_empty() {
             return Ok(vec![]);
        }

        // 1. Embed
        let texts: Vec<String> = items.iter().map(|(_, c, _)| c.clone()).collect();
        let embeddings = self.embedder.embed(texts).await?;

        // 2. Prepare Arrow Arrays
        let keys: Vec<String> = items.iter().map(|(k, _, _)| k.clone()).collect();
        let contents: Vec<String> = items.iter().map(|(_, c, _)| c.clone()).collect();
        let metadatas: Vec<String> = items.iter().map(|(_, _, m)| serde_json::to_string(m).unwrap_or_default()).collect();

        let dim = embeddings[0].len();
        let total_values = embeddings.len() * dim;
        let mut flat_embeddings = Vec::with_capacity(total_values);
        for emb in &embeddings {
            flat_embeddings.extend_from_slice(emb);
        }

        let key_array = StringArray::from(keys);
        let content_array = StringArray::from(contents);
        let metadata_array = StringArray::from(metadatas);
        let values_array = Float32Array::from(flat_embeddings);
        let inner_field = Arc::new(Field::new("item", DataType::Float32, true));
        let fixed_size_list = FixedSizeListArray::try_new(inner_field.clone(), dim as i32, Arc::new(values_array), None)?;

        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Utf8, false),
            Field::new("vector", DataType::FixedSizeList(inner_field, dim as i32), false),
            Field::new("content", DataType::Utf8, false),
            Field::new("metadata", DataType::Utf8, false),
        ]));

        let batch = RecordBatch::try_new(schema.clone(), vec![
            Arc::new(key_array),
            Arc::new(fixed_size_list),
            Arc::new(content_array),
            Arc::new(metadata_array),
        ])?;

        // 3. Write to Lance
        let path = &self.path;
        let write_params = WriteParams {
            mode: if std::path::Path::new(path).exists() {
                 WriteMode::Append
            } else {
                 WriteMode::Create
            },
            ..Default::default()
        };

        let stream = RecordBatchIterator::new(vec![Ok(batch)], schema);
        Dataset::write(stream, path, Some(write_params)).await?;

        // Return dummy IDs (0) as Lance uses internal row IDs which change on compaction
        Ok(vec![0; items.len()])
    }

    async fn search(&self, query: &str, k: usize) -> Result<Vec<SearchResult>> {
        if !std::path::Path::new(&self.path).exists() {
            return Ok(vec![]);
        }

        let dataset = self.get_dataset().await?;
        let emb = self.embedder.embed(vec![query.to_string()]).await?;
        if emb.is_empty() {
             return Ok(vec![]);
        }
        let query_vec = &emb[0];

        // Lance search
        // Note: Default distance is L2.
        // We project columns we need.
        let mut scanner = dataset.scan();
        let query_arr = Float32Array::from(query_vec.clone());
        scanner.nearest("vector", &query_arr, k)?;
        scanner.project(&["key", "metadata", "_distance"])?;

        let results = scanner.try_into_stream().await?;

        let mut final_results = Vec::new();

        let mut stream = results;
        while let Some(batch) = stream.next().await {
            let batch = batch?;

            let key_col = batch.column_by_name("key").context("Missing key column")?;
            let meta_col = batch.column_by_name("metadata").context("Missing metadata column")?;
            let dist_col = batch.column_by_name("_distance").context("Missing _distance column")?;

            let key_arr = key_col.as_any().downcast_ref::<StringArray>().context("Invalid key column type")?;
            let meta_arr = meta_col.as_any().downcast_ref::<StringArray>().context("Invalid metadata column type")?;
            let dist_arr = dist_col.as_any().downcast_ref::<Float32Array>().context("Invalid distance column type")?;

            for i in 0..batch.num_rows() {
                let key = key_arr.value(i).to_string();
                let meta_str = meta_arr.value(i);
                let dist = dist_arr.value(i);

                let metadata: serde_json::Value = serde_json::from_str(meta_str).unwrap_or(serde_json::Value::Null);
                let uri = metadata.get("uri").and_then(|v| v.as_str()).unwrap_or(&key).to_string();

                // Convert L2 distance to something like a score.
                // Closer to 0 is better.
                // SimpleVectorStore returns cosine similarity (higher is better, 1.0 max).
                // Let's invert it arbitrarily or use 1/(1+dist).
                let score = 1.0 / (1.0 + dist);

                final_results.push(SearchResult {
                    key,
                    score,
                    metadata,
                    uri
                });
            }
        }

        // Lance nearest returns top k globally, so we should have roughly k items.
        // We might want to sort by score descending just in case.
        final_results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        Ok(final_results)
    }

    async fn get_id(&self, key: &str) -> Result<Option<usize>> {
         if !std::path::Path::new(&self.path).exists() {
            return Ok(None);
        }
        let dataset = self.get_dataset().await?;
        // Quote key to be safe
        let count = dataset.count_rows(Some(format!("key = '{}'", key.replace("'", "\\'")))).await?;
        if count > 0 {
            // Return dummy ID 0 to match add() return value
            Ok(Some(0))
        } else {
            Ok(None)
        }
    }

    fn flush(&self) -> Result<()> {
        // Lance writes are atomic
        Ok(())
    }
}

#[cfg(all(test, feature = "lance-storage"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct MockEmbedder;
    #[async_trait]
    impl Embedder for MockEmbedder {
        async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
            Ok(vec![vec![0.1; 384]; texts.len()])
        }
    }

    #[tokio::test]
    async fn test_lance_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let namespace = "test_ns";

        let embedder = Arc::new(MockEmbedder);
        let store = LanceVectorStore::new_with_embedder(namespace, path, embedder).unwrap();

        // 1. Add item
        let metadata = serde_json::json!({"type": "test"});
        let id = store.add("key1", "hello world", metadata.clone()).await.unwrap();
        assert_eq!(id, 0);

        // 2. Get ID (check existence)
        let exists = store.get_id("key1").await.unwrap();
        assert!(exists.is_some());

        let missing = store.get_id("key2").await.unwrap();
        assert!(missing.is_none());

        // 3. Search
        let results = store.search("hello", 5).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].key, "key1");
    }
}
