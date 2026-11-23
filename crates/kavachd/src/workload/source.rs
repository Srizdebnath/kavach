//! Where pod metadata (labels, namespace, service account) comes from. Every source yields a
//! Kubernetes `PodList` JSON document; only the fields Kavach matches on are decoded.
//!
//! * `kubelet`   — `GET <kubelet_url>/pods` (the node's own pods; RBAC `nodes/proxy` get).
//! * `apiserver` — `GET /api/v1/pods?fieldSelector=spec.nodeName=<node>` (RBAC `pods` list).
//! * `file`      — a `PodList` JSON file (`kubectl get pods -o json`), for tests and air-gapped
//!   setups; re-read on every resync.
//!
//! Each fetch is a full list (re-listed every `resync_secs`, and at once when a pod cgroup
//! appears whose pod is not known yet), so there is no watch state to lose.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kavach_policy::workload::{PodIdentity, render_spiffe};
use serde::Deserialize;

use super::http::{self, Url};
use super::{K8sConfig, SourceKind};

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct PodList {
    items: Vec<Pod>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Pod {
    metadata: Meta,
    spec: Spec,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Meta {
    uid: String,
    name: String,
    namespace: String,
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Spec {
    service_account_name: String,
    node_name: String,
}

/// Pods by UID. Pods bound to another node are skipped when `node` is given.
pub fn parse_pod_list(
    json: &[u8],
    node: Option<&str>,
    trust_domain: &str,
    template: &str,
) -> Result<HashMap<String, PodIdentity>> {
    let list: PodList = serde_json::from_slice(json).context("decoding PodList JSON")?;
    let mut out = HashMap::new();
    for p in list.items {
        if p.metadata.uid.is_empty() {
            continue;
        }
        if let Some(n) = node
            && !p.spec.node_name.is_empty()
            && p.spec.node_name != n
        {
            continue;
        }
        let mut id = PodIdentity {
            uid: p.metadata.uid,
            namespace: if p.metadata.namespace.is_empty() {
                "default".into()
            } else {
                p.metadata.namespace
            },
            name: p.metadata.name,
            service_account: if p.spec.service_account_name.is_empty() {
                "default".into()
            } else {
                p.spec.service_account_name
            },
            labels: p.metadata.labels,
            spiffe_id: None,
        };
        id.spiffe_id = render_spiffe(template, trust_domain, &id);
        out.insert(id.uid.clone(), id);
    }
    Ok(out)
}

pub trait Source: Send {
    fn fetch(&mut self) -> Result<HashMap<String, PodIdentity>>;
    fn describe(&self) -> String;
}

struct FileSource {
    path: PathBuf,
    node: String,
    td: String,
    template: String,
}

impl Source for FileSource {
    fn fetch(&mut self) -> Result<HashMap<String, PodIdentity>> {
        let b = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        parse_pod_list(&b, Some(&self.node), &self.td, &self.template)
    }
    fn describe(&self) -> String {
        format!("file {}", self.path.display())
    }
}

struct HttpSource {
    url: Url,
    token_file: Option<PathBuf>,
    tls: Option<Arc<rustls::ClientConfig>>,
    node: String,
    td: String,
    template: String,
}

impl Source for HttpSource {
    fn fetch(&mut self) -> Result<HashMap<String, PodIdentity>> {
        // Re-read every time: projected service-account tokens rotate.
        let token = match &self.token_file {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading token {}", p.display()))?,
            ),
            None => None,
        };
        let body = http::get(
            &self.url,
            token.as_deref(),
            self.tls.as_ref(),
            Duration::from_secs(10),
        )
        .with_context(|| format!("GET {}:{}{}", self.url.host, self.url.port, self.url.path))?;
        parse_pod_list(&body, Some(&self.node), &self.td, &self.template)
    }
    fn describe(&self) -> String {
        format!(
            "{}://{}:{}{}",
            if self.url.tls { "https" } else { "http" },
            self.url.host,
            self.url.port,
            self.url.path
        )
    }
}

/// Percent-encode a query value (node names are DNS subdomains, but be strict anyway).
fn query_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Build the configured source (reads the CA bundle now, the token on every fetch).
pub fn build(cfg: &K8sConfig) -> Result<Box<dyn Source>> {
    let node = cfg.node();
    let (td, template) = (cfg.trust_domain.clone(), cfg.spiffe_template.clone());
    let base = match cfg.source {
        SourceKind::File => {
            if cfg.pods_file.as_os_str().is_empty() {
                bail!("[k8s] source = \"file\" needs pods_file");
            }
            return Ok(Box::new(FileSource {
                path: cfg.pods_file.clone(),
                node,
                td,
                template,
            }));
        }
        SourceKind::Kubelet => {
            let base = if cfg.kubelet_url.is_empty() {
                format!("https://{node}:10250")
            } else {
                cfg.kubelet_url.trim_end_matches('/').to_owned()
            };
            format!("{base}/pods")
        }
        SourceKind::Apiserver => {
            let base = if !cfg.api_server.is_empty() {
                cfg.api_server.trim_end_matches('/').to_owned()
            } else {
                match (
                    std::env::var("KUBERNETES_SERVICE_HOST"),
                    std::env::var("KUBERNETES_SERVICE_PORT"),
                ) {
                    (Ok(h), Ok(p)) if h.contains(':') => format!("https://[{h}]:{p}"),
                    (Ok(h), Ok(p)) => format!("https://{h}:{p}"),
                    _ => bail!(
                        "[k8s] source = \"apiserver\": set api_server (not running in a pod, so \
                         KUBERNETES_SERVICE_HOST is unset)"
                    ),
                }
            };
            format!(
                "{base}/api/v1/pods?fieldSelector=spec.nodeName%3D{}",
                query_escape(&node)
            )
        }
    };
    let url = Url::parse(&base)?;
    let tls = if url.tls {
        let ca = std::fs::read(&cfg.ca_file)
            .with_context(|| format!("reading CA bundle {}", cfg.ca_file.display()))?;
        Some(http::tls_config(&ca).with_context(|| cfg.ca_file.display().to_string())?)
    } else {
        None
    };
    let token_file = (!cfg.token_file.as_os_str().is_empty()).then(|| cfg.token_file.clone());
    Ok(Box::new(HttpSource {
        url,
        token_file,
        tls,
        node,
        td,
        template,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const PODS: &str = r#"{
  "kind": "PodList", "apiVersion": "v1",
  "items": [
    {"metadata": {"name": "db-0", "namespace": "prod", "uid": "1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d",
                  "labels": {"app": "db", "tier": "data"}},
     "spec": {"nodeName": "node-1", "serviceAccountName": "db"},
     "status": {"phase": "Running"}},
    {"metadata": {"name": "web", "namespace": "dev", "uid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
     "spec": {"nodeName": "node-1"}},
    {"metadata": {"name": "elsewhere", "namespace": "prod", "uid": "ffffffff-0000-1111-2222-333333333333"},
     "spec": {"nodeName": "node-2"}},
    {"metadata": {"name": "no-uid"}}
  ]
}"#;

    #[test]
    fn pod_lists_decode_with_spiffe_ids() {
        let t = kavach_policy::workload::DEFAULT_SPIFFE_TEMPLATE;
        let pods = parse_pod_list(PODS.as_bytes(), Some("node-1"), "cluster.local", t).unwrap();
        assert_eq!(
            pods.len(),
            2,
            "other node's pod and the uid-less item are skipped"
        );
        let db = &pods["1b3c5e7a-2d4f-4a6b-8c9d-0e1f2a3b4c5d"];
        assert_eq!(db.namespace, "prod");
        assert_eq!(db.labels["app"], "db");
        assert_eq!(
            db.spiffe_id.as_deref(),
            Some("spiffe://cluster.local/ns/prod/sa/db")
        );
        let web = &pods["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"];
        assert_eq!(web.service_account, "default");
        assert!(web.labels.is_empty());
        assert!(parse_pod_list(b"not json", None, "td", t).is_err());
        assert_eq!(
            parse_pod_list(PODS.as_bytes(), None, "td", t)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn query_values_are_escaped() {
        assert_eq!(query_escape("node-1.example"), "node-1.example");
        assert_eq!(query_escape("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn sources_build_from_config() {
        let mut c = K8sConfig {
            node_name: "node-1".into(),
            ..Default::default()
        };
        c.source = SourceKind::File;
        assert!(build(&c).is_err(), "file source needs pods_file");
        c.pods_file = "/nonexistent/pods.json".into();
        let mut s = build(&c).unwrap();
        assert!(s.fetch().is_err());
        c.source = SourceKind::Kubelet;
        c.ca_file = "/nonexistent/ca.crt".into();
        assert!(build(&c).err().unwrap().to_string().contains("CA bundle"));
        c.kubelet_url = "http://127.0.0.1:10255/".into();
        assert_eq!(build(&c).unwrap().describe(), "http://127.0.0.1:10255/pods");
        c.source = SourceKind::Apiserver;
        c.api_server = "http://127.0.0.1:8001".into();
        assert_eq!(
            build(&c).unwrap().describe(),
            "http://127.0.0.1:8001/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-1"
        );
    }
}
