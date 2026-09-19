"""
REVENANT — Kubernetes & Cloud-Native Security Adapters
Provides adapters for cluster and container security posture:
- Kubescape: NSA/CISA and MITRE posture scanning
- kube-bench: CIS Kubernetes Benchmark audits
- Falco: Runtime container behavior and anomaly detection
"""

from adapters.kubernetes.falco_adapter import FalcoAdapter
from adapters.kubernetes.kube_bench_adapter import KubeBenchAdapter
from adapters.kubernetes.kubescape_adapter import KubescapeAdapter

__all__ = ["KubescapeAdapter", "KubeBenchAdapter", "FalcoAdapter"]
