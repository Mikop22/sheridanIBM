import type { Vulnerability } from "@/lib/types/vulnerability";

// SIMULATED DATA: replace through lib/api/vulnerabilities.ts when FastAPI is available.
export const mockVulnerabilities: Vulnerability[] = [
  { id: "CVE-2025-44228", title: "Remote code execution in edge gateway", asset: "prod-edge-01", service: "API Gateway", cvss: 9.8, epss: 0.94, priority: "Critical", detected: "12 min ago" },
  { id: "CVE-2025-10947", title: "Authentication bypass via crafted session token", asset: "auth-service", service: "Identity", cvss: 9.1, epss: 0.87, priority: "Critical", detected: "34 min ago" },
  { id: "CVE-2024-6387", title: "Race condition in OpenSSH server", asset: "bastion-east", service: "Remote Access", cvss: 8.1, epss: 0.78, priority: "High", detected: "2 hr ago" },
  { id: "CVE-2025-24813", title: "Path equivalence vulnerability in Apache Tomcat", asset: "customer-portal", service: "Web Application", cvss: 7.5, epss: 0.69, priority: "High", detected: "4 hr ago" },
  { id: "CVE-2024-3094", title: "Supply-chain backdoor in compression library", asset: "analytics-worker", service: "Data Pipeline", cvss: 7.8, epss: 0.52, priority: "High", detected: "6 hr ago" },
  { id: "CVE-2025-21298", title: "Memory corruption in document parser", asset: "finance-laptop-42", service: "Endpoint Fleet", cvss: 8.8, epss: 0.38, priority: "Medium", detected: "1 day ago" },
];
