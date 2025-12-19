---
title: "Security Event Framework for AI Systems"
abbrev: "AI Security Events"
docname: draft-iqbal-rosomakho-ai-security-events-00
category: info
ipr: trust200902
submissiontype: IETF
area: Security
stand_alone: yes
keyword:
  - AI
  - Security Events
  - Telemetry
  - Logging
  - AI Agents

author:
  - name: Jawaid Iqbal
    role: editor
    organization: Zscaler
    email: jiqbal@zscaler.com
  - name: Yaroslav Rosomakho
    role: editor
    organization: Zscaler
    email: yrosomakho@zscaler.com

normative:
  RFC2119:
  RFC8174:

informative:

---

# Abstract

This specification defines a comprehensive security event framework for monitoring AI agent systems, including agentic AI workflows, autonomous agent architectures, and tool-calling protocols. While motivated by the Model Context Protocol (MCP), the framework applies broadly to any AI system exhibiting agent-like behaviors, addressing critical gaps in traditional security monitoring through standardized event taxonomies, correlation schemas, and detection approaches specifically designed for AI-mediated data access and semantic transformation. The specification defines five security event categories: Discovery, Risk Assessment, Data Access, Policy Enforcement, and Semantic Data Lineage. Event schemas are designed as a domain-specific profile that complements existing security event standards (CEF, LEEF, OCSF) rather than replacing them, enabling integration with existing SIEM infrastructure while providing AI-specific semantics. The framework is protocol-agnostic, supporting multiple AI agent frameworks including the Model Context Protocol (MCP), LangChain, and others. It explicitly addresses diverse deployment patterns including direct client-server, gateway consolidation, embedded AI, autonomous agents, and multi-agent orchestration.

# Introduction

## Problem Statement

AI agent systems introduce autonomous capabilities that transcend traditional security monitoring approaches. These systems invoke tools to access enterprise data, transform information semantically through large language model processing, maintain conversational context across sessions, and operate through protocols designed for functionality rather than security observability.

Existing security frameworks generate events based on file movement, network traffic patterns, and process execution. These approaches fail to detect AI-mediated data exfiltration where:

* Sensitive data is compressed semantically (500KB document to 2KB summary)
* Information is aggregated across multiple non-sensitive sources
* Data transformations occur within encrypted AI API calls
* Context persists across sessions without explicit data transfer

This specification provides a domain-specific event taxonomy for AI agent systems that complements existing security event standards (CEF, LEEF, OCSF) by adding AI-specific semantics while maintaining interoperability with existing SIEM infrastructure. Rather than replacing existing standards, this framework extends them to address unique AI agent security requirements.

## Critical Security Gaps

Analysis of production AI agent deployments has identified four critical architectural gaps in traditional security systems:

Gap 1: Visibility Gap. AI capabilities embedded within trusted domains bypass inspection. Production evidence indicates 30-40% of AI traffic operates within trusted application contexts, creating significant blind spots in security monitoring.

Gap 2: The Decoupled Transaction Gap. Traditional security logging assumes a synchronous, 1:1 relationship between a network session and a data transfer (e.g., a single POST request containing a file). However, modern AI agent architectures frequently utilize split-transaction data transfer workflows to optimize latency and scale. In these workflows, the client first negotiates an upload via a metadata-only API call (transmitting filename, size, and user context), receiving a pre-signed URL or storage token in response. The actual binary payload is subsequently transmitted to a distinct storage endpoint (often a different domain or CDN) in a separate, unauthenticated HTTP session. Standard logging treats these as two unrelated events, resulting in "orphan" data transfers where binary content cannot be attributed to the initiating user, session, or policy context.

Gap 3: Governance Gap. Unauthorized AI infrastructure including shadow servers, gateways, and agents operates without security oversight, creating unmanaged pathways for data access.

Gap 4: Persistence Gap. Data converted to vector embeddings becomes unscannable by traditional DLP systems while retaining complete semantic meaning, enabling covert data persistence.

## Motivating Use Cases

This event taxonomy enables SOC teams to address concrete security scenarios:

Use Case 1: Shadow AI Detection. Discover unauthorized AI agents, servers, and gateways operating on corporate networks through Discovery and Risk events, enabling governance and compliance enforcement.

Use Case 2: Data Exfiltration Detection. Correlate Data Access and Semantic Lineage events to identify when confidential data is summarized and sent to unauthorized destinations, detecting exfiltration that bypasses traditional DLP.

Use Case 3: Policy Compliance. Monitor Policy Enforcement events to ensure AI agents respect data classification policies, rate limits, and access controls, generating compliance audit trails for regulatory requirements.

## Scope and Applicability

This framework applies to:

* AI agent protocols: Model Context Protocol, LangChain, AutoGPT, OpenAI Assistants API, and custom implementations
* Tool-calling systems: Agents that invoke functions, tools, or plugins to access data
* Deployment patterns: Direct connections, gateway consolidation, embedded AI, autonomous agents, and multi-agent orchestration
* Environment types: Browser extensions, desktop applications, cloud services, edge devices, and containerized infrastructure

This specification does not cover general AI model training security, prompt injection detection, or AI output quality monitoring, which are addressed in separate standards.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 {{RFC2119}} and RFC 8174 {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

## Terminology

This specification uses the following terms:

AI Agent: An autonomous system that uses foundation models to reason, make decisions, and invoke tools to accomplish objectives.

Tool: A capability exposed to an AI agent for accessing resources (file access, API calls, database queries).

Gateway: An intermediary layer consolidating multiple backend servers behind a unified endpoint.

Semantic transformation: AI model processing that changes data representation while preserving meaning.

Semantic lineage: Tracking how sensitive meaning propagates across AI transformations.

Shadow deployment: Unauthorized AI infrastructure operating without enterprise security oversight (e.g., personal Claude Desktop clients connecting to corporate MCP servers).

# Architecture Overview

## Event Flow Model

Security events in AI agent systems originate from multiple execution points. A generalized flow encompasses:

User → AI agent → [gateway] → Tool server → Resource → AI model → Output → Destination

Each transition point represents a potential security event generation surface. Events flow to security controls (Endpoint, SSE) for analysis, correlation, and policy enforcement.

### Split-Transaction Transfer Model

To accurately log AI data access, the event model MUST account for decoupled transfer patterns common in Large Language Model (LLM) interactions. This specification defines the "Split-Transaction" model as a sequence where:

1. Initiation Event: The agent or user signals intent to transfer data. This event carries the Semantic Context (User ID, Session ID, Filename) but lacks the Binary Payload.
2. Authorization Event: The service returns a temporary access token or pre-signed URI.
3. Transfer Event: The payload is transmitted to the authorized URI. This event carries the Binary Payload but often lacks the Semantic Context (due to the absence of authentication cookies or headers on the storage endpoint).

This taxonomy introduces the correlation_id field (Section 4.1) specifically to allow implementations to link the Initiation Event with the Transfer Event, ensuring that the semantic meaning of the data remains attached to the binary transfer in the security log.

## Detection Surfaces

Implementations MAY observe AI agent activity through multiple detection surfaces:

* Network telemetry: Inline inspection of AI agent protocol traffic
* Endpoint telemetry: Process monitoring, file access, configuration discovery
* Gateway instrumentation: Event generation from consolidation layers
* Runtime instrumentation: SDK-based event generation within applications
* Cloud service logging: API logs from AI model providers and SaaS platforms

No single detection surface provides complete visibility. Implementations SHOULD combine multiple surfaces for comprehensive monitoring.

## Deployment Pattern Taxonomy

AI agent systems deploy through five distinct architectural patterns, each with unique security characteristics:

### Direct Client-Server Pattern

AI clients connect directly to individual tool servers. Detection requires monitoring N independent server connections. Common in desktop AI applications connecting to cloud storage APIs. Security characteristic: Distributed detection requirements across multiple endpoints.

### Gateway Pattern

Multiple tool servers consolidated behind a unified gateway endpoint. Reduces detection complexity to single observation point. Common in enterprise deployments with centralized AI infrastructure. Security characteristic: Simplified monitoring through consolidation layer.

### Embedded AI Pattern

AI capabilities integrated within trusted applications. Traditional security boundaries assume trusted environment and skip inspection. Production evidence shows 30-40% of AI traffic in this category. Security characteristic: Requires endpoint-based detection since network inspection is bypassed.

### Autonomous Agent Pattern

AI systems operating with minimal human supervision. Extended execution timeframes and complex tool chaining. Common in workflow automation and research applications. Security characteristic: Long-running sessions requiring persistent event correlation.

### Multi-Agent Orchestration Pattern

Multiple AI agents collaborating on complex tasks. Agent-to-agent communication introduces lateral movement concerns. Emerging in advanced enterprise AI deployments. Security characteristic: Requires tracking information flow across agent boundaries.

# Event Taxonomy

This section defines the core event categories that comprise the AI agent security monitoring framework.

## Discovery Events

Discovery events identify the presence of AI agent infrastructure components regardless of authorization status. These events provide the foundation for asset inventory and governance enforcement.

Event Types:
* agent_discovered: AI client or agent detected
* server_discovered: Tool server endpoint identified  
* gateway_discovered: Consolidation layer detected

Discovery events MUST include: component_type, protocol_indicators, detection_method, confidence_score

## Risk Assessment Events

Risk events evaluate discovered components against security policies and enterprise governance frameworks. These events enable differentiation between authorized and shadow infrastructure.

Event Types:
* shadow_component_detected: Unauthorized infrastructure identified
* policy_violation_detected: Component operates outside governance framework
* risk_score_calculated: Risk assessment completed for component

Risk events MUST include: risk_score, policy_reference, authorization_status, remediation_priority

## Data Access Events

Data Access events track tool invocations that retrieve, process, or transmit enterprise data. These events enable monitoring of what data AI agents access and where it flows.

Event Types:
* tool_invoked: Agent initiated tool execution
* data_retrieved: Tool returned data to agent
* data_transmitted: Data sent to external destination

Data Access events MUST include: tool_name, data_sensitivity, access_result, byte_count

## Policy Enforcement Events

Policy Enforcement events document security control decisions applied to AI agent operations. These events provide audit trails for compliance and enable detection of policy bypass attempts.

Event Types:
* access_allowed: Operation permitted by policy
* access_denied: Operation blocked by policy
* quota_exceeded: Rate limit or threshold exceeded

Policy Enforcement events MUST include: policy_decision, enforcement_point, justification, override_status

## Semantic Data Lineage Events

Semantic Lineage events track how meaning propagates through AI transformations, addressing the unique challenge of semantic data exfiltration where traditional content-based monitoring fails.

Event Types:
* semantic_transformation_detected: Data meaning altered by AI processing
* context_persisted: Information stored in conversational memory
* meaning_exfiltrated: Semantic content transmitted to unauthorized destination

Semantic Lineage events MUST include: transformation_type, meaning_preservation_score, source_data_classification, destination_classification

# Common Event Schema Elements

All events in this taxonomy MUST include the following core fields:

## Correlation Fields

* event_id: Unique identifier for this event (UUID format)
* correlation_id: Links related events in multi-step operations
* parent_event_id: References causative event in chain
* session_id: Groups events within single user session

The correlation_id field specifically addresses the Split-Transaction Transfer Model by enabling implementations to link metadata-rich initiation events with payload-carrying transfer events.

## Temporal Fields

* timestamp: Event generation time (ISO 8601 format)
* event_duration_ms: Operation execution time
* detection_latency_ms: Time between occurrence and detection

## Identity Fields

* user_id: Authenticated user identifier
* agent_id: AI agent instance identifier
* organization_id: Tenant or organization identifier

## Network Context

* source_ip: Origin address
* destination_ip: Target address
* destination_domain: Target hostname
* protocol: Network protocol identifier

## Data Classification

* data_sensitivity: Classification level (public, internal, confidential, restricted)
* data_categories: Types of data accessed (PII, financial, source_code, etc.)
* regulatory_flags: Applicable compliance frameworks (GDPR, HIPAA, SOC2, etc.)

# Security Considerations

## Privacy Protection

Implementations MUST minimize collection of AI prompt content and model responses. Detection SHOULD rely on metadata analysis (timing patterns, payload sizes, endpoint signatures) rather than deep packet inspection of conversational content.

## False Positive Management

Multi-signal fusion is RECOMMENDED to achieve >95% detection confidence. Single-signal detection typically achieves only 50-70% confidence. Implementations SHOULD correlate User-Agent analysis, temporal patterns, payload characteristics, and endpoint signatures.

## Evasion Resistance

Adversaries may attempt to evade detection through:
* Protocol mimicry: Making AI traffic appear as standard HTTPS
* Timing manipulation: Introducing artificial delays to avoid burst detection
* Payload obfuscation: Encrypting or encoding transmitted data

Implementations SHOULD employ multiple detection surfaces and regularly update signatures based on emerging evasion techniques.

## Encrypted Traffic Handling

AI agent protocols predominantly use TLS 1.3 encryption. Implementations requiring deep inspection MUST implement TLS interception with appropriate user consent, certificate management, and privacy safeguards. Metadata-only detection is RECOMMENDED as a privacy-preserving alternative.

# IANA Considerations

This document has no IANA actions.

# Appendix A. JSON Schema Examples

This appendix provides informative examples of event schemas in JSON format.

## Discovery Event Example

~~~json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "agent_discovered",
  "event_category": "discovery",
  "timestamp": "2025-12-16T08:04:34Z",
  "component_type": "desktop_agent",
  "agent_signature": {
    "user_agent": "Unknown(connect-es/1.6.1)",
    "electron_version": "37.7.0",
    "protocol_indicators": ["grpc-web", "mcp-client"]
  },
  "detection_method": "network_telemetry",
  "confidence_score": 0.95,
  "network_context": {
    "source_ip": "10.0.0.25",
    "destination_domain": "api2.cursor.sh",
    "destination_ip": "52.32.178.96",
    "protocol": "https",
    "tls_version": "1.3"
  }
}
~~~

## Data Access Event Example

~~~json
{
  "event_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "event_type": "data_transmitted",
  "event_category": "data_access",
  "timestamp": "2025-12-16T08:10:10Z",
  "correlation_id": "upload-session-12345",
  "tool_name": "filesyncservice.fsuploadfile",
  "data_sensitivity": "internal",
  "data_categories": ["source_code"],
  "byte_count": 10515,
  "user_id": "user@example.com",
  "session_id": "session-abc123",
  "network_context": {
    "source_ip": "10.0.0.25",
    "destination_domain": "us-only.gcpp.cursor.sh",
    "destination_ip": "18.237.140.108"
  }
}
~~~

## Semantic Lineage Event Example

~~~json
{
  "event_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "event_type": "semantic_transformation_detected",
  "event_category": "semantic_lineage",
  "timestamp": "2025-12-16T08:10:20Z",
  "transformation_type": "summarization",
  "meaning_preservation_score": 0.92,
  "source_data_classification": "confidential",
  "destination_classification": "public_ai_service",
  "transformation_details": {
    "input_size_bytes": 524288,
    "output_size_bytes": 2048,
    "compression_ratio": 256.0,
    "semantic_categories_preserved": ["financial_data", "business_strategy"]
  }
}
~~~

# Appendix B. Production Validation Evidence

NOTE: This appendix is informative, not normative. It provides empirical validation of the event schemas and detection methods.

## Dataset Characteristics

Traffic Source: Zscaler Zero Trust Exchange (ZIA)
Collection Date: December 16, 2025
Collection Time: 07:45:35 - 08:13:45 UTC (28 minutes)
Total Transactions: 656 HTTP/HTTPS requests
Users: 2 authenticated
SSL Inspection: 90.7% coverage
TLS Versions: TLS 1.3 (81%), TLS 1.2 (10%)
Geographic Flow: Egypt (client) → United States (AI services)

## Detection Results Summary

Agent Activity Events Generated: 63
Semantic Exposure Events Generated: 5
Detection Rate: 100% (all agent traffic identified)
False Positive Rate: 0% (no browser traffic misclassified)
Precision: 100% (63 true positives, 0 false positives)

Shadow MCP Client Identified: Cursor IDE v2.2.23
Data Exfiltrated: 57,324 bytes (56 KB) via file synchronization operations
Cross-Border Transfer: Egypt → United States (potential GDPR/data residency implications)
Traditional DLP Bypass: Confirmed (zero violations flagged while 56 KB uploaded)

## Shadow MCP Client Signature Evidence

User-Agent: "Unknown(connect-es/1.6.1)"
gRPC-Web client library (https://github.com/connectrpc/connect-es)
53 occurrences (84% of Cursor traffic)
Does NOT declare agent identity ("Cursor IDE")
Only identified through correlation with "Electron/37.7.0" signatures

Endpoint Pattern: api2.cursor.sh/aiserver.v1.*
Service-oriented architecture (gRPC-style)
File synchronization: /aiserver.v1.filesyncservice/fsuploadfile
Dashboard services: /dashboardservice/getteams, /getuserprivacymode

Temporal Pattern - Sub-Second Burst:

~~~
08:04:34.000 UTC | POST | /dashboardservice/getteams (1,396 bytes)
08:04:34.000 UTC | POST | /aiservice/checkfeaturesstatus (2,252 bytes)
08:04:34.000 UTC | POST | /dashboardservice/getuserprivacymode (1,417 bytes)
08:04:34.000 UTC | POST | /aiservice/checknumberconfigs (1,908 bytes)
~~~

Four API calls within same second timestamp - impossible for human browser interaction (typical human latency: 1-2 seconds minimum).

Payload Asymmetry: 18.37x request/response ratio
Total uploaded: 57,324 bytes
Total received: 3,120 bytes
Pattern indicates: large context uploads → minimal AI acknowledgment responses
Characteristic of code assistant workflows

## Semantic Data Exposure Evidence

File Upload Sequence: 5 transactions over 5 seconds to us-only.gcpp.cursor.sh:443

~~~
Transaction #557 | 08:10:10 UTC | 10,515 bytes
Transaction #559 | 08:10:11 UTC | 11,085 bytes
Transaction #562 | 08:10:12 UTC | 11,991 bytes
Transaction #564 | 08:10:14 UTC | 12,519 bytes (largest)
Transaction #567 | 08:10:15 UTC | 11,214 bytes
~~~

Endpoint: /aiserver.v1.filesyncservice/fsuploadfile
Method: POST
User-Agent: Unknown(connect-es/1.6.1)
Total: 57,324 bytes (56 KB)

Traditional DLP Bypass Mechanism:
NO file downloads (HTTP GET with file MIME types)
NO file attachments
NO cloud storage sync operations
Data transmitted in HTTP POST bodies (gRPC-Web serialization)
Traditional DLP verdict: ALLOWED (saw only "POST → 200 OK")
Reality: 56 KB source code uploaded to third-party AI service

Payload sizes (10-12 KB) and /filesyncservice/fsuploadfile endpoint consistent with source code files being transmitted to AI backend.

## Detection Signature Validation

Multi-Signal Fusion Results:
Single Signal Confidence: ~50-70%
Multi-Signal (3+) Confidence: >95%
Validated Approach: Correlate User-Agent + Temporal + Payload + Endpoint patterns

Telemetry Source Effectiveness:

| Signal Type | Effectiveness | Production Coverage |
|------------|---------------|---------------------|
| User-Agent Analysis | HIGH | 84% identified by this alone |
| Temporal Burst Patterns | HIGH | 100% distinguishes agent from human |
| Payload Asymmetry | HIGH | 100% identifies context upload |
| Endpoint Pattern Matching | HIGH | 100% matches gRPC-Web signatures |
| Protocol Analysis | MEDIUM | Confirms desktop agent vs. browser |
| TLS Fingerprinting | LOW | Supporting evidence only |

## Privacy Compliance

Data Captured (Metadata Only):
Byte counts, User-Agent strings, URL endpoints, timestamps, TLS characteristics, IP addresses, HTTP status codes, protocol identifiers

Data NOT Captured (Content):
No AI prompt content, no AI response content, no source code inspected, no variable/function names, no semantic meaning from code

Assessment: COMPLIANT with privacy requirements. All detection via network metadata. No deep packet inspection of AI prompts/responses performed or required.

## Key Validation Conclusions

1. Shadow MCP clients exist in production - Cursor IDE detected operating without governance oversight, generating 10.8% of observed traffic

2. Network telemetry is sufficient - 100% detection accuracy using User-Agent + timing + endpoints + payloads; no cloud API integration required

3. Cloud-side governance has no visibility - Zero integration detected; Cursor operated independently of enterprise AI control planes

4. Semantic exposure bypasses traditional DLP - 56 KB uploaded via API payloads invisible to file-based DLP systems

5. Event schemas are implementable - Valid JSON events successfully generated from real network transactions

6. Privacy can be preserved - Metadata-only detection achieved 100% accuracy while protecting user privacy

## Validation Limitations

Single organization: Traffic from one enterprise deployment
Limited duration: 28-minute observation window
Known agent type: Cursor IDE; other AI agents may exhibit different signatures
No false negative analysis: Ground truth not available for comparison
Geographic specificity: Egypt-to-US flows; other regions may differ

Despite these limitations, validation demonstrates the specification addresses an observable, real-world security gap with implementable detection methods.
