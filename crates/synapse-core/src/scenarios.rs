use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;

const DEFAULT_REMOTE_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/pmaojo/synapse-engine/main/scenarios/registry.json";
const DEFAULT_MAX_DOWNLOAD_SIZE_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RegistryEntry {
    pub name: String,
    pub description: String,
    pub version: String,
    pub location: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub ontologies: Vec<String>,
    #[serde(default)]
    pub data_files: Vec<String>,
    #[serde(default)]
    pub docs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioSourcePolicy {
    #[serde(default)]
    pub allow_remote_scenarios: bool,
    #[serde(default)]
    pub allowed_registry_hosts: Vec<String>,
    #[serde(default = "default_max_download_size_bytes")]
    pub max_download_size_bytes: usize,
}

fn default_max_download_size_bytes() -> usize {
    DEFAULT_MAX_DOWNLOAD_SIZE_BYTES
}

impl Default for ScenarioSourcePolicy {
    fn default() -> Self {
        Self {
            allow_remote_scenarios: false,
            allowed_registry_hosts: Vec::new(),
            max_download_size_bytes: default_max_download_size_bytes(),
        }
    }
}

impl ScenarioSourcePolicy {
    fn ensure_remote_allowed(&self, url: &str, operation: &str) -> Result<()> {
        if !self.allow_remote_scenarios {
            anyhow::bail!(
                "Remote scenario content loading denied by policy for {operation}: {url}"
            );
        }
        let parsed = reqwest::Url::parse(url)
            .with_context(|| format!("Invalid URL for scenario {operation}: {url}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Scenario {operation} URL missing host: {url}"))?;
        let is_allowed = self
            .allowed_registry_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host));
        if !is_allowed {
            anyhow::bail!(
                "Scenario {operation} host '{host}' is not allowlisted; allowed_registry_hosts must include this host"
            );
        }
        Ok(())
    }
}

pub struct ScenarioManager {
    base_path: PathBuf,
    client: reqwest::Client,
    policy: ScenarioSourcePolicy,
    remote_registry_url: String,
}

impl ScenarioManager {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self::with_policy(base_path, ScenarioSourcePolicy::default())
    }

    pub fn with_policy(base_path: impl AsRef<Path>, policy: ScenarioSourcePolicy) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS))
            .build()
            .expect("valid reqwest client config for ScenarioManager");
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            client,
            policy,
            remote_registry_url: DEFAULT_REMOTE_REGISTRY_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn with_policy_and_registry_url(
        base_path: impl AsRef<Path>,
        policy: ScenarioSourcePolicy,
        remote_registry_url: String,
    ) -> Self {
        let mut manager = Self::with_policy(base_path, policy);
        manager.remote_registry_url = remote_registry_url;
        manager
    }

    /// Fetches the list of available scenarios from the registry.
    pub async fn list_scenarios(&self) -> Result<Vec<RegistryEntry>> {
        let local_registry = self.base_path.join("scenarios").join("registry.json");
        if local_registry.exists() {
            let content = fs::read_to_string(local_registry).await?;
            let registry: Vec<RegistryEntry> = serde_json::from_str(&content)?;
            return Ok(registry);
        }

        self.policy
            .ensure_remote_allowed(&self.remote_registry_url, "registry fetch")?;
        tracing::info!(
            operation = "list_scenarios",
            remote_enabled = self.policy.allow_remote_scenarios,
            host_allowlist_count = self.policy.allowed_registry_hosts.len(),
            "Applying synapse remote source policy"
        );

        let resp = self
            .client
            .get(&self.remote_registry_url)
            .send()
            .await
            .context("Failed to fetch remote registry")?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch registry: {}",
                resp.status()
            ));
        }

        let registry: Vec<RegistryEntry> =
            resp.json().await.context("Failed to parse registry JSON")?;
        Ok(registry)
    }

    /// Installs a scenario by name.
    /// Returns the path to the installed scenario directory.
    pub async fn install_scenario(&self, name: &str) -> Result<PathBuf> {
        let registry = self.list_scenarios().await?;
        let entry = registry
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| anyhow::anyhow!("Scenario '{}' not found in registry", name))?;

        let scenario_dir = self.base_path.join("scenarios").join(name);
        fs::create_dir_all(&scenario_dir).await?;

        let local_source = self.base_path.join("scenarios").join(name);
        if local_source.exists() && local_source.join("manifest.json").exists() {
            return self
                .install_from_local_path(&local_source, &scenario_dir)
                .await;
        }

        if entry.location.starts_with("http") {
            return self
                .install_from_remote(&entry.location, &scenario_dir)
                .await;
        }

        Err(anyhow::anyhow!(
            "Could not find installation source for scenario '{}'",
            name
        ))
    }

    async fn install_from_local_path(&self, source: &Path, dest: &Path) -> Result<PathBuf> {
        if source.canonicalize()? == dest.canonicalize().unwrap_or(dest.to_path_buf()) {
            eprintln!("Source and destination are the same, skipping copy.");
            return Ok(dest.to_path_buf());
        }

        let manifest_path = source.join("manifest.json");
        fs::copy(&manifest_path, dest.join("manifest.json")).await?;

        let content = fs::read_to_string(&manifest_path).await?;
        let manifest: Manifest = serde_json::from_str(&content)?;

        if !manifest.ontologies.is_empty() {
            let schema_dest = dest.join("schema");
            fs::create_dir_all(&schema_dest).await?;
            for file in &manifest.ontologies {
                let src = source.join("schema").join(file);
                if src.exists() {
                    fs::copy(&src, schema_dest.join(file)).await?;
                }
            }
        }

        if !manifest.data_files.is_empty() {
            let data_dest = dest.join("data");
            fs::create_dir_all(&data_dest).await?;
            for file in &manifest.data_files {
                let src = source.join("data").join(file);
                if src.exists() {
                    fs::copy(&src, data_dest.join(file)).await?;
                }
            }
        }

        if !manifest.docs.is_empty() {
            let docs_dest = dest.join("docs");
            fs::create_dir_all(&docs_dest).await?;
            for file in &manifest.docs {
                let src = source.join("docs").join(file);
                if src.exists() {
                    fs::copy(&src, docs_dest.join(file)).await?;
                }
            }
        }

        Ok(dest.to_path_buf())
    }

    async fn install_from_remote(&self, base_url: &str, dest: &Path) -> Result<PathBuf> {
        self.policy
            .ensure_remote_allowed(base_url, "scenario install")?;
        tracing::info!(
            operation = "install_scenario",
            remote_enabled = self.policy.allow_remote_scenarios,
            max_download_size_bytes = self.policy.max_download_size_bytes,
            "Applying synapse remote source policy"
        );

        let clean_base = base_url.trim_end_matches('/');

        let manifest_url = format!("{}/manifest.json", clean_base);
        let content = self.download_text_limited(&manifest_url).await?;
        fs::write(dest.join("manifest.json"), &content).await?;

        let manifest: Manifest = serde_json::from_str(&content)?;

        if !manifest.ontologies.is_empty() {
            let schema_dest = dest.join("schema");
            fs::create_dir_all(&schema_dest).await?;
            for file in &manifest.ontologies {
                let url = format!("{}/schema/{}", clean_base, file);
                self.download_file(&url, &schema_dest.join(file)).await?;
            }
        }

        if !manifest.data_files.is_empty() {
            let data_dest = dest.join("data");
            fs::create_dir_all(&data_dest).await?;
            for file in &manifest.data_files {
                let url = format!("{}/data/{}", clean_base, file);
                self.download_file(&url, &data_dest.join(file)).await?;
            }
        }

        if !manifest.docs.is_empty() {
            let docs_dest = dest.join("docs");
            fs::create_dir_all(&docs_dest).await?;
            for file in &manifest.docs {
                let url = format!("{}/docs/{}", clean_base, file);
                self.download_file(&url, &docs_dest.join(file)).await?;
            }
        }

        Ok(dest.to_path_buf())
    }

    async fn download_text_limited(&self, url: &str) -> Result<String> {
        let bytes = self.download_bytes_limited(url).await?;
        String::from_utf8(bytes).context("Downloaded content was not valid UTF-8")
    }

    async fn download_file(&self, url: &str, dest: &Path) -> Result<()> {
        let bytes = self.download_bytes_limited(url).await?;
        fs::write(dest, bytes).await?;
        Ok(())
    }

    async fn download_bytes_limited(&self, url: &str) -> Result<Vec<u8>> {
        self.policy.ensure_remote_allowed(url, "file download")?;

        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download {}: status {}",
                url,
                resp.status()
            ));
        }

        if let Some(content_length) = resp.content_length() {
            let max = u64::try_from(self.policy.max_download_size_bytes)
                .context("max_download_size_bytes does not fit in u64")?;
            if content_length > max {
                anyhow::bail!(
                    "Remote download exceeds policy limit ({} > {} bytes)",
                    content_length,
                    self.policy.max_download_size_bytes
                );
            }
        }

        let bytes = resp.bytes().await?;
        if bytes.len() > self.policy.max_download_size_bytes {
            anyhow::bail!(
                "Remote download exceeds policy limit ({} > {} bytes)",
                bytes.len(),
                self.policy.max_download_size_bytes
            );
        }
        Ok(bytes.to_vec())
    }

    pub async fn get_manifest(&self, scenario_name: &str) -> Result<Manifest> {
        let manifest_path = self
            .base_path
            .join("scenarios")
            .join(scenario_name)
            .join("manifest.json");
        if !manifest_path.exists() {
            let local_dev_path = self
                .base_path
                .join("scenarios")
                .join(scenario_name)
                .join("manifest.json");
            if local_dev_path.exists() {
                let content = fs::read_to_string(local_dev_path).await?;
                return Ok(serde_json::from_str(&content)?);
            }
            return Err(anyhow::anyhow!(
                "Scenario '{}' is not installed",
                scenario_name
            ));
        }
        let content = fs::read_to_string(manifest_path).await?;
        Ok(serde_json::from_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_temp_workspace() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("synapse-policy-tests-{unique}"));
        std::fs::create_dir_all(&path).expect("create temp workspace directory");
        path
    }

    async fn spawn_static_server(routes: Vec<(&'static str, &'static str)>) -> Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0_u8; 4096];
                let Ok(size) = socket.read(&mut buf).await else {
                    continue;
                };
                let req = String::from_utf8_lossy(&buf[..size]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let body = routes
                    .iter()
                    .find_map(|(route, body)| if *route == path { Some(*body) } else { None });
                let response = if let Some(body) = body {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        Ok(addr)
    }

    async fn write_registry(workspace: &Path, body: String) -> Result<()> {
        let scenarios_dir = workspace.join("scenarios");
        fs::create_dir_all(&scenarios_dir).await?;
        fs::write(scenarios_dir.join("registry.json"), body).await?;
        Ok(())
    }

    #[tokio::test]
    async fn remote_install_denied_by_default() -> Result<()> {
        let workspace = make_temp_workspace();
        let addr = spawn_static_server(vec![]).await?;
        write_registry(
            &workspace,
            format!(
                r#"[{{"name":"core","description":"d","version":"1","location":"http://{addr}/scenario"}}]"#
            ),
        )
        .await?;

        let manager = ScenarioManager::new(&workspace);
        let err = manager.install_scenario("core").await.unwrap_err();
        assert!(err.to_string().contains("denied by policy"));
        Ok(())
    }

    #[tokio::test]
    async fn allowlisted_host_remote_install_succeeds() -> Result<()> {
        let workspace = make_temp_workspace();
        let manifest = r#"{"name":"core","version":"1.0.0","description":"ok","ontologies":["o.ttl"],"data_files":["d.csv"],"docs":["readme.md"]}"#;
        let server = spawn_static_server(vec![
            ("/scenario/manifest.json", manifest),
            ("/scenario/schema/o.ttl", "@prefix : <http://example/> ."),
            ("/scenario/data/d.csv", "a,b\n1,2\n"),
            ("/scenario/docs/readme.md", "# docs"),
        ])
        .await?;

        write_registry(
            &workspace,
            format!(
                r#"[{{"name":"core","description":"d","version":"1","location":"http://{server}/scenario"}}]"#
            ),
        )
        .await?;

        let policy = ScenarioSourcePolicy {
            allow_remote_scenarios: true,
            allowed_registry_hosts: vec!["127.0.0.1".to_string()],
            max_download_size_bytes: 1024 * 1024,
        };
        let manager = ScenarioManager::with_policy(&workspace, policy);
        let installed = manager.install_scenario("core").await?;

        assert!(installed.join("manifest.json").exists());
        assert!(installed.join("schema").join("o.ttl").exists());
        Ok(())
    }

    #[tokio::test]
    async fn non_allowlisted_host_remote_install_is_rejected() -> Result<()> {
        let workspace = make_temp_workspace();
        let server = spawn_static_server(vec![]).await?;
        write_registry(
            &workspace,
            format!(
                r#"[{{"name":"core","description":"d","version":"1","location":"http://{server}/scenario"}}]"#
            ),
        )
        .await?;

        let policy = ScenarioSourcePolicy {
            allow_remote_scenarios: true,
            allowed_registry_hosts: vec!["example.com".to_string()],
            max_download_size_bytes: 1024 * 1024,
        };
        let manager = ScenarioManager::with_policy(&workspace, policy);
        let err = manager.install_scenario("core").await.unwrap_err();
        assert!(err.to_string().contains("not allowlisted"));
        Ok(())
    }

    #[tokio::test]
    async fn remote_install_rejects_oversize_download() -> Result<()> {
        let workspace = make_temp_workspace();
        let big_manifest = format!(
            "{{\"name\":\"core\",\"version\":\"1.0.0\",\"description\":\"{}\",\"ontologies\":[],\"data_files\":[],\"docs\":[]}}",
            "x".repeat(2048)
        );
        let server = spawn_static_server(vec![(
            "/scenario/manifest.json",
            Box::leak(big_manifest.into_boxed_str()),
        )])
        .await?;
        write_registry(
            &workspace,
            format!(
                r#"[{{"name":"core","description":"d","version":"1","location":"http://{server}/scenario"}}]"#
            ),
        )
        .await?;

        let policy = ScenarioSourcePolicy {
            allow_remote_scenarios: true,
            allowed_registry_hosts: vec!["127.0.0.1".to_string()],
            max_download_size_bytes: 512,
        };
        let manager = ScenarioManager::with_policy(&workspace, policy);
        let err = manager.install_scenario("core").await.unwrap_err();
        assert!(err.to_string().contains("exceeds policy limit"));
        Ok(())
    }

    #[tokio::test]
    async fn remote_registry_fetch_denied_when_policy_disallows_remote() -> Result<()> {
        let workspace = make_temp_workspace();
        let server = spawn_static_server(vec![("/registry.json", "[]")]).await?;

        let manager = ScenarioManager::with_policy_and_registry_url(
            &workspace,
            ScenarioSourcePolicy::default(),
            format!("http://{server}/registry.json"),
        );
        let err = manager.list_scenarios().await.unwrap_err();
        assert!(err.to_string().contains("denied by policy"));
        Ok(())
    }
}
