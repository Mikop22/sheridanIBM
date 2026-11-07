import { mockVulnerabilities } from "@/lib/data/mock-vulnerabilities";
import type { Vulnerability } from "@/lib/types/vulnerability";

/** UI data boundary. Replace with a typed FastAPI fetch without changing dashboard components. */
export function fetchVulnerabilityOverview(): Vulnerability[] { return mockVulnerabilities; }
