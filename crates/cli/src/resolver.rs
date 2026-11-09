//! AgentSandbox resolver (M3): sandbox name → pod (spike (d) proved CR name ==
//! pod name), via the `oc` subprocess honoring KUBECONFIG — no kube-rs.
//!
//! Naming (plan §6): OpenShell sandboxes are `AgentSandbox` CRs named
//! `<workspace>--<name>` in the namespace (default `openshell`, env
//! `SYNC_NAMESPACE`). The CLI accepts either the full CR name
//! (`default--sync-oc`) or the short name (`sync-oc` + workspace, default
//! `default`). The matching pod is verified Running before we hand it to the
//! transport — errors are loud (a not-yet-running sandbox must never surface
//! as a confusing exec failure later).

use std::io;
use std::path::Path;
use std::process::Command;

/// A resolved sync target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub pod: String,
    pub namespace: String,
}

/// Default namespace: env `SYNC_NAMESPACE`, else `openshell` (the OpenShell
/// install namespace from M0.0).
pub fn default_namespace() -> String {
    match std::env::var("SYNC_NAMESPACE") {
        Ok(ns) if !ns.is_empty() => ns,
        _ => "openshell".to_string(),
    }
}

/// Build the `oc` argv for one read-only query. Pure — unit-tested; the
/// process is spawned only by [`resolve`].
fn oc_argv(oc: &str, kubeconfig: Option<&Path>, args: &[&str]) -> Vec<String> {
    let mut argv = vec![oc.to_string()];
    if let Some(kc) = kubeconfig {
        argv.push("--kubeconfig".into());
        argv.push(kc.display().to_string());
    }
    argv.extend(args.iter().map(|s| s.to_string()));
    argv
}

/// Parse `oc get <kind> -o name` output into bare names
/// (`agentsandbox.agents.x-k8s.io/default--sync-oc` → `default--sync-oc`).
/// Blank lines are skipped; lines without a `/` are taken verbatim (defensive
/// against oc output changes).
fn cr_names(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.rsplit('/').next().unwrap_or(l).to_string())
        .collect()
}

/// Match a sandbox request against the CR names on the cluster: exact match
/// first, then `<workspace>--<short>`. Returns the CR (= pod) name.
fn match_cr(candidates: &[String], sandbox: &str, workspace: &str) -> Option<String> {
    if sandbox.contains("--") {
        return candidates.iter().find(|c| c.as_str() == sandbox).cloned();
    }
    let qualified = format!("{workspace}--{sandbox}");
    candidates.iter().find(|c| c.as_str() == qualified).cloned()
}

/// Run one oc query, mapping failures to loud errors that carry stderr.
fn run_oc(oc: &str, kubeconfig: Option<&Path>, args: &[&str]) -> io::Result<String> {
    let argv = oc_argv(oc, kubeconfig, args);
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| io::Error::other(format!("spawn {}: {e}", argv[0])))?;
    if !out.status.success() {
        // oc's client-go spews a memcache line per API-group probe before the
        // real error — keep only the LAST stderr line (the actionable one) so
        // the UI alert stays readable.
        let stderr = String::from_utf8_lossy(&out.stderr);
        let last = stderr
            .lines()
            .rev()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .unwrap_or("");
        Err(io::Error::other(format!(
            "`{}` failed ({}): {}",
            argv.join(" "),
            out.status,
            last
        )))
    } else {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Resolve a sandbox reference to its running pod.
///
/// * `sandbox` — full CR name (`default--sync-oc`) or short name (`sync-oc`).
/// * `workspace` — workspace prefix for short names (OpenShell: `default`).
/// * `kubeconfig` — explicit kubeconfig (None → oc's own resolution).
/// * `oc` — the oc binary (env `SYNC_OC` for testability).
pub fn resolve(
    sandbox: &str,
    workspace: &str,
    kubeconfig: Option<&Path>,
    oc: &str,
) -> io::Result<Resolved> {
    let namespace = default_namespace();

    let listing = run_oc(
        oc,
        kubeconfig,
        &[
            "get",
            "sandbox.agents.x-k8s.io",
            "-n",
            &namespace,
            "-o",
            "name",
        ],
    )?;
    let candidates = cr_names(&listing);
    let cr = match_cr(&candidates, sandbox, workspace).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no AgentSandbox matches {sandbox:?} (workspace {workspace:?}) in namespace \
                 {namespace}; found: {}{}",
                candidates.join(", "),
                if candidates.is_empty() { "(none)" } else { "" }
            ),
        )
    })?;

    // CR name == pod name (M0 spike (d)) — still verify the pod exists AND is
    // Running before handing it to the transport.
    let phase = run_oc(
        oc,
        kubeconfig,
        &[
            "get",
            "pod",
            &cr,
            "-n",
            &namespace,
            "-o",
            "jsonpath={.status.phase}",
        ],
    )?;
    if phase.trim() != "Running" {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "sandbox pod {cr} in {namespace} is not Running (phase {:?}) — sync needs a \
                 live sandbox",
                phase.trim()
            ),
        ));
    }
    Ok(Resolved { pod: cr, namespace })
}

// ---------------------------------------------------------------------------
// Tests — parse/argv only (no cluster access anywhere in this module's tests).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn oc_argv_kubeconfig_optional() {
        assert_eq!(
            oc_argv("oc", None, &["get", "pods"]),
            vec!["oc".to_string(), "get".to_string(), "pods".to_string()]
        );
        let kc = PathBuf::from("/tmp/opencode/kube.cfg");
        assert_eq!(
            oc_argv("oc", Some(kc.as_path()), &["get", "pods"]),
            vec![
                "oc".to_string(),
                "--kubeconfig".to_string(),
                "/tmp/opencode/kube.cfg".to_string(),
                "get".to_string(),
                "pods".to_string(),
            ]
        );
        // SYNC_OC shim: a non-default oc binary lands in argv[0].
        assert_eq!(oc_argv("shim-oc", None, &["version"])[0], "shim-oc");
    }

    #[test]
    fn cr_names_parse_and_trim() {
        let out = "sandbox.agents.x-k8s.io/default--sync-oc\n\
                   agentsandbox.agents.x-k8s.io/team--build\n\n  \n";
        assert_eq!(
            cr_names(out),
            vec!["default--sync-oc".to_string(), "team--build".to_string()]
        );
        assert!(cr_names("").is_empty());
        // Defensive: a bare name without a kind prefix still parses.
        assert_eq!(cr_names("default--sync-oc"), vec!["default--sync-oc"]);
    }

    #[test]
    fn match_cr_exact_then_workspace_qualified() {
        let candidates = vec!["default--sync-oc".to_string(), "team--build".to_string()];
        // Full name matches exactly.
        assert_eq!(
            match_cr(&candidates, "default--sync-oc", "default"),
            Some("default--sync-oc".into())
        );
        // Short name qualifies with the workspace.
        assert_eq!(
            match_cr(&candidates, "sync-oc", "default"),
            Some("default--sync-oc".into())
        );
        // Wrong workspace → no match (a short name must never silently hit
        // another workspace's sandbox).
        assert_eq!(match_cr(&candidates, "build", "default"), None);
        assert_eq!(
            match_cr(&candidates, "build", "team"),
            Some("team--build".into())
        );
        // Unknown short name → None (resolve turns this into a loud error).
        assert_eq!(match_cr(&candidates, "nope", "default"), None);
        // A full-name request with -- inside must match EXACTLY, never prefix.
        assert_eq!(match_cr(&candidates, "default--sync", "default"), None);
    }

    #[test]
    fn default_namespace_env_override() {
        // SYNC_NAMESPACE unset → the OpenShell install namespace.
        // (set only when absent; parallel tests may share the env)
        if std::env::var("SYNC_NAMESPACE").is_err() {
            assert_eq!(default_namespace(), "openshell");
        }
    }
}
