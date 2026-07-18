---
tags: [cloud, containers, kubernetes]
status: learning
---

# Container & Kubernetes Security

> Containers and orchestration add layers, each with its own misconfigurations. You don't need to be a k8s admin, but an AppSec engineer must know the common risks and the vocabulary.

## Container (Docker) risks
| Risk | Fix |
|---|---|
| **Running as root** in the container | `USER` non-root; drop capabilities |
| **`--privileged` / host mounts** | Container escape → host takeover. Never `--privileged`; no `/var/run/docker.sock` mount |
| **Secrets in image layers / ENV** | Multi-stage builds, secret mounts, not `ENV`/`ARG` → [[Secrets-Management]] |
| **Vulnerable base image** | Scan with **Trivy/Grype**; minimal/distroless base; pin digests |
| **Writable / bloated image** | Read-only root FS; minimal packages |
| **Unpinned base (`:latest`)** | Pin by digest → [[CI-CD-and-Software-Supply-Chain]] |

## Kubernetes risks
| Area | Risk |
|---|---|
| **RBAC** | Over-broad roles, `cluster-admin` sprawl — the k8s version of IAM least-privilege |
| **Pod Security** | Privileged pods, `hostNetwork`/`hostPID`, `hostPath` mounts → node takeover |
| **Secrets** | k8s Secrets are base64 (not encrypted) by default; enable encryption at rest, use external secret stores |
| **Network** | No NetworkPolicies = flat network, free lateral movement; default-deny egress/ingress |
| **Exposed components** | Kubelet `:10250`, etcd, dashboard without auth → cluster takeover (often via [[SSRF-Server-Side-Request-Forgery]]) |
| **Supply chain** | Unsigned images, no admission control |
| **Service account tokens** | Auto-mounted, over-privileged → escalation |

## Key defenses
- **Pod Security Standards** (restricted profile), admission controllers (OPA/Gatekeeper, Kyverno).
- **NetworkPolicies** default-deny; segment namespaces.
- **RBAC least privilege**; disable auto-mount of SA tokens when unused.
- **Image scanning + signing** in CI (Trivy + cosign); admission control rejects unsigned/vulnerable images.
- Encrypt etcd/secrets at rest; external secret managers.
- Runtime security (Falco) for detection.

## Practice + interview
- **kubernetes-goat**, **kube-goat** — deliberately vulnerable clusters.
- **Interview:** *Difference between `--privileged` and normal containers?* (Privileged ≈ root on the host — near-guaranteed escape.) *Are k8s Secrets secure by default?* (No — base64, need encryption at rest + external store.) *How do you limit blast radius in a cluster?* (RBAC least privilege, NetworkPolicies default-deny, Pod Security restricted, no host mounts.)

---
**Related:** [[Cloud-Security-AWS-Focus]] · [[CI-CD-and-Software-Supply-Chain]] · [[SSRF-Server-Side-Request-Forgery]]
