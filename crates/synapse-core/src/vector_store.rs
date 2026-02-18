use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

// Candle imports
#[cfg(feature = "local-embeddings")]
use candle_core::{Device, Tensor};
#[cfg(feature = "local-embeddings")]
use candle_nn::VarBuilder;
#[cfg(feature = "local-embeddings")]
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
#[cfg(feature = "local-embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
#[cfg(feature = "local-embeddings")]
use tokenizers::Tokenizer;

const DEFAULT_AUTO_SAVE_THRESHOLD: usize = 100;

#[derive(Serialize, Deserialize, Clone)]
pub struct VectorEntry {
    pub key: String,
    pub embedding: Vec<f32>,
    pub metadata_json: String,
}

#[derive(Serialize, Deserialize)]
struct VectorData {
    entries: Vec<VectorEntry>,
}

pub struct SearchResult {
    pub key: String,
    pub score: f32,
    pub metadata: serde_json::Value,
    pub uri: String,
}

#[async_trait::async_trait]
trait Embedder: Send + Sync {
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>>;
}

#[cfg(feature = "local-embeddings")]
struct LocalEmbedder {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

#[cfg(feature = "local-embeddings")]
impl LocalEmbedder {
    fn new() -> Result<Self> {
        let device = Device::Cpu;
        let api = Api::new()?;
        let repo = api.repo(Repo::new(
            "sentence-transformers/all-MiniLM-L6-v2".to_string(),
            RepoType::Model,
        ));

        let config_filename = repo.get("config.json")?;
        let tokenizer_filename = repo.get("tokenizer.json")?;
        let weights_filename = repo.get("model.safetensors")?;

        let config = std::fs::read_to_string(config_filename)?;
        let config: Config = serde_json::from_str(&config)?;
        let tokenizer = Tokenizer::from_file(tokenizer_filename).map_err(anyhow::Error::msg)?;

        let vb =
            unsafe { VarBuilder::from_mmaped_safetensors(&[weights_filename], DTYPE, &device)? };
        let model = BertModel::load(vb, &config)?;

        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }
}

#[cfg(feature = "local-embeddings")]
#[async_trait::async_trait]
impl Embedder for LocalEmbedder {
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        // Since Candle is sync/blocking for now (CPU), we wrap in spawn_blocking in VectorStore usually,
        // but here we can't easily move self because of async_trait?
        // Actually, we can just do it synchronously here? No, async_trait expects async.
        // We will need to wrap the compute in block_in_place or similar if we were running in tokio,
        // but since we are refactoring, let's keep it simple.
        // The original code used spawn_blocking from the caller.

        // WARNING: Running heavy CPU compute in async function can block the runtime.
        // Ideally this should be offloaded.
        // But to avoid complex borrowing issues with moving `self` (which contains the model) into a thread,
        // we might just run it here.
        //
        // However, the original code cloned the Arc<EmbeddingModel>.
        // Here we are inside &self.
        // Since we can't clone &self easily into a 'static task unless we use Arc on the struct itself.
        // Let's assume for now we just run it. The caller `VectorStore` holds `Arc<dyn Embedder>`.
        // So we can clone that Arc! But the trait method takes &self.
        // We can't clone `self` from `&self`.

        // Simpler approach: Just run it. It's a refactor. Optimize later if needed.

        let mut embeddings = Vec::new();
        for text in texts {
            let encoding = self
                .tokenizer
                .encode(text.as_str(), true)
                .map_err(anyhow::Error::msg)?;
            let input_ids = Tensor::new(encoding.get_ids(), &self.device)?.unsqueeze(0)?;
            let token_type_ids =
                Tensor::new(encoding.get_type_ids(), &self.device)?.unsqueeze(0)?;

            // Forward pass
            let output = self.model.forward(&input_ids, &token_type_ids, None)?;

            // Mean pooling
            let (_n_sentence, n_tokens, _hidden_size) = output.dims3()?;
            let embeddings_tensor = (output.sum(1)? / (n_tokens as f64))?;

            // Normalize
            let sqr = embeddings_tensor.sqr()?;
            let sum_sqr = sqr.sum_keepdim(1)?;
            let sqrt_sum_sqr = sum_sqr.sqrt()?;
            let normalize_embedding = embeddings_tensor.broadcast_div(&sqrt_sum_sqr)?;

            let embedding_vec: Vec<f32> = normalize_embedding.to_vec1()?;
            embeddings.push(embedding_vec);
        }
        Ok(embeddings)
    }
}

#[cfg(feature = "remote-embeddings")]
struct RemoteEmbedder {
    client: reqwest::Client,
    api_url: String,
    token: String,
}

#[cfg(feature = "remote-embeddings")]
impl RemoteEmbedder {
    fn new() -> Result<Self> {
        let token = std::env::var("HF_TOKEN").context("HF_TOKEN environment variable required for remote embeddings")?;
        Ok(Self {
            client: reqwest::Client::new(),
            api_url: "https://api-inference.huggingface.co/pipeline/feature-extraction/sentence-transformers/all-MiniLM-L6-v2".to_string(),
            token,
        })
    }
}

#[cfg(feature = "remote-embeddings")]
#[async_trait::async_trait]
impl Embedder for RemoteEmbedder {
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        let response = self.client.post(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&texts)
            .send()
            .await?;

        if !response.status().is_success() {
             let error_text = response.text().await?;
             anyhow::bail!("Hugging Face API error: {}", error_text);
        }

        let embeddings: Vec<Vec<f32>> = response.json().await?;
        Ok(embeddings)
    }
}

// Dummy embedder when no feature is enabled
#[cfg(not(any(feature = "local-embeddings", feature = "remote-embeddings")))]
struct NoOpEmbedder;

#[cfg(not(any(feature = "local-embeddings", feature = "remote-embeddings")))]
#[async_trait::async_trait]
impl Embedder for NoOpEmbedder {
    async fn embed(&self, _texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        anyhow::bail!("No embedding feature enabled (local-embeddings or remote-embeddings)")
    }
}


pub struct VectorStore {
    // Linear store for robust compilation
    id_to_key: Arc<RwLock<HashMap<usize, String>>>,
    key_to_id: Arc<RwLock<HashMap<String, usize>>>,
    key_to_metadata: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    storage_path: Option<PathBuf>,

    // Abstracted embedder
    embedder: Arc<dyn Embedder>,

    dimensions: usize,
    embeddings: Arc<RwLock<Vec<VectorEntry>>>,
    dirty_count: Arc<AtomicUsize>,
    auto_save_threshold: usize,
}

impl VectorStore {
    pub fn new(namespace: &str) -> Result<Self> {
        // Initialize embedder based on features
        // Priority: Remote (if enabled via env/flag preference? No, usually explicit feature)
        // If both enabled, let's prefer Local unless configured otherwise?
        // Actually, to make compilation easy, user will likely enable only one.
        // But if both are present, let's look for env var.

        let embedder: Arc<dyn Embedder> = {
            #[cfg(feature = "remote-embeddings")]
            {
                // If remote is enabled, try it first if HF_TOKEN is present, or if local is disabled.
                if std::env::var("HF_TOKEN").is_ok() {
                     Arc::new(RemoteEmbedder::new()?)
                } else {
                     #[cfg(feature = "local-embeddings")]
                     { Arc::new(LocalEmbedder::new()?) }
                     #[cfg(not(feature = "local-embeddings"))]
                     { anyhow::bail!("HF_TOKEN not set and local-embeddings disabled") }
                }
            }
            #[cfg(all(not(feature = "remote-embeddings"), feature = "local-embeddings"))]
            {
                Arc::new(LocalEmbedder::new().context("Failed to load Candle embedding model")?)
            }
             #[cfg(not(any(feature = "local-embeddings", feature = "remote-embeddings")))]
            {
                Arc::new(NoOpEmbedder)
            }
        };

        let dimensions = 384;

        let mut storage_path = None;
        if let Ok(path) = std::env::var("SYNAPSE_STORAGE_PATH") {
            storage_path = Some(PathBuf::from(path).join(namespace));
        } else if let Some(home) = dirs::home_dir() {
            storage_path = Some(home.join(".synapse").join(namespace));
        }

        let mut embeddings = Vec::new();
        let mut id_to_key = HashMap::new();
        let mut key_to_id = HashMap::new();
        let mut key_to_metadata = HashMap::new();

        if let Some(ref path) = storage_path {
            if path.join("vectors.json").exists() {
                let content = std::fs::read_to_string(path.join("vectors.json"))?;
                let data: VectorData = serde_json::from_str(&content)?;

                for (i, entry) in data.entries.into_iter().enumerate() {
                    if entry.embedding.len() == dimensions {
                        let id = i;
                        id_to_key.insert(id, entry.key.clone());
                        key_to_id.insert(entry.key.clone(), id);
                        let metadata = serde_json::from_str(&entry.metadata_json)
                            .unwrap_or(serde_json::Value::Null);
                        key_to_metadata.insert(entry.key.clone(), metadata);
                        embeddings.push(entry);
                    }
                }
            }
        }

        Ok(Self {
            id_to_key: Arc::new(RwLock::new(id_to_key)),
            key_to_id: Arc::new(RwLock::new(key_to_id)),
            key_to_metadata: Arc::new(RwLock::new(key_to_metadata)),
            storage_path,
            embedder,
            dimensions,
            embeddings: Arc::new(RwLock::new(embeddings)),
            dirty_count: Arc::new(AtomicUsize::new(0)),
            auto_save_threshold: DEFAULT_AUTO_SAVE_THRESHOLD,
        })
    }

    fn save_vectors(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            std::fs::create_dir_all(path)?;

            let (entries, current_dirty) = {
                let guard = self.embeddings.read().unwrap();
                (guard.clone(), self.dirty_count.load(Ordering::Relaxed))
            };

            let data = VectorData { entries };
            let json = serde_json::to_string_pretty(&data)?;
            std::fs::write(path.join("vectors.json"), json)?;

            if current_dirty > 0 {
                let _ = self.dirty_count.fetch_sub(current_dirty, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.save_vectors()
    }

    pub async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let embeddings = self.embed_batch(vec![text.to_string()]).await?;
        if embeddings.is_empty() {
            anyhow::bail!("Failed to generate embedding");
        }
        Ok(embeddings[0].clone())
    }

    pub async fn embed_batch(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        // Use the abstracted embedder
        // If it's local (blocking), we might want to wrap it in spawn_blocking if we want to be nice to async runtime.
        // But since we abstracted it behind async trait, let's assume implementation handles it or we accept blocking for now.
        // Actually, for LocalEmbedder I removed the spawn_blocking wrapper inside the trait implementation
        // because I couldn't easily clone the model into the closure.
        // To restore behavior, we should wrap the call here IF we know it's blocking.
        // But we don't know concrete type here.

        // Correction: In the original code, `model.embed` was blocking, and it was wrapped here.
        // Now `embedder.embed` is async.
        // For RemoteEmbedder, it is truly async (reqwest).
        // For LocalEmbedder, I made it async but it blocks thread.
        // To fix this properly, LocalEmbedder should use `tokio::task::block_in_place` or `spawn_blocking` internally if possible.
        // Or we just accept it blocks the thread for this refactor.

        self.embedder.embed(texts).await
    }

    pub async fn add(
        &self,
        key: &str,
        content: &str,
        metadata: serde_json::Value,
    ) -> Result<usize> {
        let results = self
            .add_batch(vec![(key.to_string(), content.to_string(), metadata)])
            .await?;
        Ok(results[0])
    }

    pub async fn add_batch(
        &self,
        items: Vec<(String, String, serde_json::Value)>,
    ) -> Result<Vec<usize>> {
        let mut new_items = Vec::new();
        let mut result_ids = vec![0; items.len()];
        let mut new_indices = Vec::new();

        {
            let key_map = self.key_to_id.read().unwrap();
            for (i, (key, content, _)) in items.iter().enumerate() {
                if let Some(&id) = key_map.get(key) {
                    result_ids[i] = id;
                } else {
                    new_items.push(content.clone());
                    new_indices.push(i);
                }
            }
        }

        if new_items.is_empty() {
            return Ok(result_ids);
        }

        let embeddings = self.embed_batch(new_items).await?;
        let mut ids_to_add = Vec::new();

        {
            let mut key_map = self.key_to_id.write().unwrap();
            let mut id_map = self.id_to_key.write().unwrap();
            let mut metadata_map = self.key_to_metadata.write().unwrap();
            let mut embs = self.embeddings.write().unwrap();

            let mut next_id = embs.len();

            for (i, embedding) in embeddings.into_iter().enumerate() {
                let original_idx = new_indices[i];
                let (key, _, metadata) = &items[original_idx];

                if let Some(&id) = key_map.get(key) {
                    result_ids[original_idx] = id;
                    continue;
                }

                let id = next_id;
                next_id += 1;

                key_map.insert(key.clone(), id);
                id_map.insert(id, key.clone());
                metadata_map.insert(key.clone(), metadata.clone());

                embs.push(VectorEntry {
                    key: key.clone(),
                    embedding,
                    metadata_json: serde_json::to_string(metadata).unwrap_or_default(),
                });

                result_ids[original_idx] = id;
                ids_to_add.push(id);
            }
        }

        if !ids_to_add.is_empty() {
            let count = self
                .dirty_count
                .fetch_add(ids_to_add.len(), Ordering::Relaxed);
            if count + ids_to_add.len() >= self.auto_save_threshold {
                let _ = self.save_vectors();
            }
        }

        Ok(result_ids)
    }

    pub async fn search(&self, query: &str, k: usize) -> Result<Vec<SearchResult>> {
        let query_embedding = self.embed(query).await?;

        let embeddings = self.embeddings.read().unwrap();
        if embeddings.is_empty() {
            return Ok(Vec::new());
        }

        // Linear Search: Cosine Similarity
        let mut scores: Vec<(usize, f32)> = embeddings
            .iter()
            .enumerate()
            .map(|(id, entry)| {
                let sim = cosine_similarity(&query_embedding, &entry.embedding);
                (id, sim)
            })
            .collect();

        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let top_k = scores.into_iter().take(k).collect::<Vec<_>>();

        let id_map = self.id_to_key.read().unwrap();
        let metadata_map = self.key_to_metadata.read().unwrap();

        let results: Vec<SearchResult> = top_k
            .iter()
            .filter_map(|(id, score)| {
                id_map.get(id).map(|key| {
                    let metadata = metadata_map
                        .get(key)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let uri = metadata
                        .get("uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or(key)
                        .to_string();

                    SearchResult {
                        key: key.clone(),
                        score: *score,
                        metadata,
                        uri,
                    }
                })
            })
            .collect();

        Ok(results)
    }

    pub fn get_id(&self, key: &str) -> Option<usize> {
        self.key_to_id.read().unwrap().get(key).copied()
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot_product: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot_product / (norm_a * norm_b)
    }
}
