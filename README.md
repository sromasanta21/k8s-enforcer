# Zero-Trust Automated Kubernetes Security Enforcer

A cloud-native **Validating Admission Controller & Supply-Chain Policy Engine** built for bare-metal Kubernetes clusters. Intercepts API deployment requests at the control plane boundary to enforce cryptographic image provenance (Sigstore Cosign) and least-privilege runtime policies (Open Policy Agent / Rego) before workloads are scheduled.

## Architecture Overview

- **Admission Webhook Controller (`webhook-app/`):** Custom Python FastAPI HTTPS service intercepting `AdmissionReview` payloads from `kube-apiserver`, verifying Cosign signatures, and caching validated SHA-256 image digests in Redis.
- **Policy Evaluation Engine (`k8s-manifests/`):** Decoupled Open Policy Agent (OPA) daemon evaluating declarative Rego rules (enforcing `runAsNonRoot` and dropping Linux capabilities).
- **Bare-Metal Provisioning (`cloud-init/`):** Automated Ubuntu 26.04 Server provisioning via Subiquity/cloud-init configuring `containerd`, `kubeadm`, Calico CNI, and MetalLB.
- **Observability & Autoscaling:** Horizontal Pod Autoscaler (HPA) dynamically scaling webhook replicas under burst loads, backed by Prometheus telemetry.

## Repository Structure

```text
k8s-enforcer/
├── cloud-init/       # Autoinstall user-data files for master & worker nodes
├── webhook-app/      # Custom FastAPI admission controller, Cosign verifier & multi-stage Dockerfile
├── k8s-manifests/    # Namespace, OPA Rego ConfigMap, Redis, Webhook Deployment, HPA & NetworkPolicies
└── test-workloads/   # Verification manifests (unsigned, privileged root, and compliant pods)