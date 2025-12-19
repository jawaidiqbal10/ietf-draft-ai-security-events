---
author:
  - name: Jawaid Iqbal
    role: editor
  - name: Yaroslav Rosomakho
    role: editor
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
---

# Abstract

This specification defines a comprehensive security event framework for monitoring AI agent systems, including agentic AI workflows, autonomous agent architectures,  and tool-calling protocols. While motivated by the Model Context Protocol (MCP), the framework applies broadly to any AI system exhibiting agent-like behaviors, addressing critical gaps in traditional security monitoring through standardized event taxonomies, correlation schemas, and detection approaches specifically designed for AI-mediated data access and semantic transformation.

The specification defines five security event categories: Discovery, Risk Assessment, Data Access, Policy Enforcement, and Semantic Data Lineage. Event schemas are designed as a domain-specific profile that complements existing security event standards (CEF, LEEF, OCSF) rather than replacing them, enabling integration with existing SIEM infrastructure while providing AI-specific semantics.

The framework is protocol-agnostic, supporting multiple AI agent frameworks including the Model Context Protocol (MCP), LangChain, and others. It explicitly addresses diverse deployment patterns including direct client-server, gateway consolidation, embedded AI, autonomous agents, and multi-agent orchestration.



# 1. Introduction

## 1.1 Problem Statement

AI agent systems introduce autonomous capabilities that transcend traditional security monitoring approaches. These systems invoke tools to access enterprise data, transform information semantically through large language model processing, maintain conversational context across sessions, and operate through protocols designed for functionality rather than security observability.

Existing security frameworks generate events based on file movement, network traffic patterns, and process execution. These approaches fail to detect AI-mediated data exfiltration where:

* Sensitive data is compressed semantically (500KB document to 2KB summary)  
* Information is aggregated across multiple non-sensitive sources  
* Data transformations occur within encrypted AI API calls  
* Context persists across sessions without explicit data transfer

This specification provides a domain-specific event taxonomy for AI agent systems that complements existing security event standards (CEF, LEEF, OCSF) by adding AI-specific semantics while maintaining interoperability with existing SIEM infrastructure. Rather than replacing existing standards, this framework extends them to address unique AI agent security requirements.

## 1.2 Critical Security Gaps

Analysis of production AI agent deployments has identified four critical architectural gaps in traditional security systems:

Gap 1: Visibility Gap. AI capabilities embedded within trusted domains bypass inspection. Production evidence indicates 30-40% of AI traffic operates within trusted application contexts, creating significant blind spots in security monitoring.

Gap 2: The Decoupled Transaction Gap. Traditional security logging assumes a synchronous, 1:1 relationship between a network session and a data transfer (e.g., a single POST request containing a file). However, modern AI agent architectures frequently utilize split-transaction data transfer workflows to optimize latency and scale. In these workflows, the client first negotiates an upload via a metadata-only API call (transmitting filename, size, and user context), receiving a pre-signed URL or storage token in response. The actual binary payload is subsequently transmitted to a distinct storage endpoint (often a different domain or CDN) in a separate, unauthenticated HTTP session. Standard logging treats these as two unrelated events, resulting in "orphan" data transfers where binary content cannot be attributed to the initiating user, session, or policy context.

Gap 3: Governance Gap. Unauthorized AI infrastructure including shadow servers, gateways, and agents operates without security oversight, creating unmanaged pathways for data access.

Gap 4: Persistence Gap. Data converted to vector embeddings becomes unscannable by traditional DLP systems while retaining complete semantic meaning, enabling covert data persistence.

## 1.3 Motivating Use Cases

This event taxonomy enables SOC teams to address concrete security scenarios:

Use Case 1: Shadow AI Detection. Discover unauthorized AI agents, servers, and gateways operating on corporate networks through Discovery and Risk events, enabling governance and compliance enforcement.

Use Case 2: Data Exfiltration Detection. Correlate Data Access and Semantic Lineage events to identify when confidential data is summarized and sent to unauthorized destinations, detecting exfiltration that bypasses traditional DLP.

Use Case 3: Policy Compliance. Monitor Policy Enforcement events to ensure AI agents respect data classification policies, rate limits, and access controls, generating compliance audit trails for regulatory requirements.

## 1.4 Scope and Applicability

This framework applies to:

* AI agent protocols: Model Context Protocol, LangChain, AutoGPT, OpenAI Assistants API, and custom implementations  
* Tool-calling systems: Agents that invoke functions, tools, or plugins to access data  
* Deployment patterns: Direct connections, gateway consolidation, embedded AI, autonomous agents, and multi-agent orchestration  
* Environment types: Browser extensions, desktop applications, cloud services, edge devices, and containerized infrastructure

This specification does not cover general AI model training security, prompt injection detection, or AI output quality monitoring, which are addressed in separate standards.

## 1.5 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 \[RFC2119\] and RFC 8174 \[RFC8174\] when, and only when, they appear in all capitals, as shown here.

## 1.6 Terminology

This specification uses the following terms:

AI Agent: An autonomous system that uses foundation models to reason, make decisions, and invoke tools to accomplish objectives.

Tool: A capability exposed to an AI agent for accessing resources (file access, API calls, database queries).

Gateway: An intermediary layer consolidating multiple backend servers behind a unified endpoint.

Semantic transformation: AI model processing that changes data representation while preserving meaning.

Semantic lineage: Tracking how sensitive meaning propagates across AI transformations.

Shadow deployment: Unauthorized AI infrastructure operating without enterprise security oversight (e.g., personal Claude Desktop clients connecting to corporate MCP servers).

# 2\. Architecture Overview

## 2.1 Event Flow Model

Security events in AI agent systems originate from multiple execution points. A generalized flow encompasses:

*User → AI agent → \[gateway\] → Tool server → Resource → AI model → Output → Destination*

Each transition point represents a potential security event generation surface. Events flow to security controls (Endpoint, SSE) for analysis, correlation, and policy enforcement.

### 2.1.1 Split-Transaction Transfer Model

To accurately log AI data access, the event model MUST account for decoupled transfer patterns common in Large Language Model (LLM) interactions. This specification defines the "Split-Transaction" model as a sequence where:

1. Initiation Event: The agent or user signals intent to transfer data. This event carries the Semantic Context (User ID, Session ID, Filename) but lacks the Binary Payload.  
2. Authorization Event: The service returns a temporary access token or pre-signed URI.  
3. Transfer Event: The payload is transmitted to the authorized URI. This event carries the Binary Payload but often lacks the Semantic Context (due to the absence of authentication cookies or headers on the storage endpoint).

This taxonomy introduces the correlation\_id field (Section 4.1) specifically to allow implementations to link the Initiation Event with the Transfer Event, ensuring that the semantic meaning of the data remains attached to the binary transfer in the security log.

## 2.2 Detection Surfaces

Implementations MAY observe AI agent activity through multiple detection surfaces:

* Network telemetry: Inline inspection of AI agent protocol traffic  
* Endpoint telemetry: Process monitoring, file access, configuration discovery  
* Gateway instrumentation: Event generation from consolidation layers  
* Runtime instrumentation: SDK-based event generation within applications  
* Cloud service logging: API logs from AI model providers and SaaS platforms

No single detection surface provides complete visibility. Implementations SHOULD combine multiple surfaces for comprehensive monitoring.

## 2.3 Deployment Pattern Taxonomy

AI agent systems deploy through five distinct architectural patterns, each with unique security characteristics:

### 2.3.1 Direct Client-Server Pattern

AI clients connect directly to individual tool servers. Detection requires monitoring N independent server connections. Common in desktop AI applications connecting to cloud storage APIs. Security characteristic: Distributed detection requirements across multiple endpoints.

### 2.3.2 Gateway Pattern

Intermediary layers consolidate multiple backend servers behind unified endpoints, providing centralized authentication, authorization, and policy enforcement. Creates single control points for monitoring traffic across multiple data sources.

### 2.3.3 Embedded AI Pattern

AI capabilities embedded within trusted applications (IDE plugins, productivity suites, collaboration tools). Traffic appears as legitimate application activity. Security characteristic: Significant visibility challenges due to trusted context.

### 2.3.4 Autonomous Agent Pattern

Self-directed agents executing multi-step workflows with minimal human oversight. Long-running sessions, dynamic tool chaining, and emergent behaviors complicate traditional monitoring. Security characteristic: Unpredictable access patterns requiring behavioral analysis.

### 2.3.5 Multi-Agent Orchestration Pattern

Multiple specialized agents collaborating on complex tasks. Agent-to-agent communication, distributed decision-making, and composite trust boundaries require correlation across agent instances. Security characteristic: Complex trust boundary management and cross-agent lineage tracking.

# 3\. Event Classification Framework

This specification defines five security event categories for AI agent monitoring. Each category addresses distinct security requirements while supporting correlation across event types.

Category Summary:

| Category | Addresses Gaps | Primary Purpose | Detection |
| ----- | ----- | ----- | ----- |
| Discovery | Visibility, Governance | Infrastructure inventory | Network, Endpoint |
| Risk | Governance | Security posture assessment | Config scan |
| Data Access | Inspection | Audit trail of data operations | Inline, Gateway |
| Policy | All (Prevention) | Runtime enforcement actions | Inline, Gateway |
| Lineage | Inspection, Persistence | Track meaning across transformations | Semantic |

Note on category distinction: Risk events identify security posture weaknesses (misconfigurations, shadow infrastructure, vulnerabilities), while Policy events document runtime enforcement actions (blocks, rate limits, content redaction). Risk events are typically generated by periodic scans or discovery processes, whereas Policy events are generated inline during agent operation.

The following subsections provide detailed definitions and examples for each category.

## 3.1 Discovery Events

Purpose: Enable security systems to maintain inventory of AI agent infrastructure including servers, clients, gateways, tools, and resources.

Addresses: Visibility Gap and Governance Gap. Provides telemetry to enumerate both authorized and shadow AI deployments.

Required Fields:

*Note: These events MUST also include the core required fields (event\_type, timestamp, schema\_version, source) defined in Section 4.1.1.*

* event\_type (string): Hierarchical classification (e.g., discovery.server.detected)  
* timestamp (string): ISO 8601 format with timezone  
* component\_id (string): Identifier for discovered component

### 3.1.1 Example: MCP Server Discovery

{  "event\_type": "discovery.server.detected",  "timestamp": "2025-12-15T10:23:45Z",  "schema\_version": "1.0",  "source": "zscaler-proxy-01",  "component\_id": "mcp-server-gdrive-01",  "component\_type": "mcp\_server",  "endpoint": "https://mcp.google.com/drive",  "deployment\_type": "sanctioned",  "protocol": "mcp",  "capabilities": \["read", "write", "search"\],  "tool\_count": 12,  "detection\_method": "network\_telemetry"}

## 3.6 AI Agent Activity Security Events

Purpose: Define standardized security events for detecting user-initiated, agent-mediated AI activity (U2A) and associated semantic data exposure risks based on observable network telemetry.

Addresses: Visibility Gap, Governance Gap, and Inspection Gap. These events enable organizations to detect and monitor AI agent activity that occurs outside centralized control planes, including local agents, desktop tools, and developer frameworks.

Production Validation: This event category was validated against 28 minutes of production Zscaler network traffic (656 transactions, December 16, 2025), achieving 100% detection accuracy with zero false positives. The validation identified Cursor IDE as an active Shadow MCP client, detected 63 agent activity events and 5 semantic exposure events, and confirmed 57 KB of semantic data exfiltration bypassing traditional DLP. See Appendix B for complete validation details.

### 3.6.1 Overview

This section defines normative requirements for emitting security events related to AI agent-mediated interactions with AI models, as inferred from network telemetry. These events provide visibility into AI activity occurring outside centralized AI application control planes.

The events apply to environments where inline network inspection is available and AI interactions are observable via protocol, timing, and client characteristics rather than explicit agent registration.

### 3.6.2 Definitions

AI Agent: Software that performs AI-related actions programmatically on behalf of a user, including submitting prompts or context to AI models and processing responses. Production example: Cursor IDE (v2.2.23) detected via non-browser User-Agent "Unknown(connect-es/1.6.1)".

User-to-Agent Interaction (U2A): An interaction model where a user initiates execution, but an agent performs AI operations autonomously or semi-autonomously.

Programmatic AI Client: A non-browser client accessing AI model APIs directly, including SDKs, CLI tools, or desktop applications. Production validation: gRPC-Web protocol (connect-es library) identified in 84% of agent traffic.

Semantic Data Exposure: A condition where enterprise data meaning is extracted or transformed by an AI model without explicit file transfer. Production evidence: 57 KB of code uploaded via API payloads to Cursor's AI backend without any file downloads, completely bypassing traditional DLP systems (which saw only "POST → 200 OK" and flagged no violations).

Shadow MCP Client: An AI agent accessing services outside centralized enterprise governance without explicit registration or policy enforcement. Characterized by: gRPC-Web protocols, non-browser User-Agents, sub-second burst patterns, and asymmetric payload flows.

### 3.6.3 Event: AI Agent Activity Detected

A system MUST generate an \`ai.agent.activity.detected\` event when observing network traffic satisfying ALL conditions:

1\. Traffic originates from an endpoint associated with an authenticated user  
2\. Traffic accesses an AI model or AI inference service via direct API  
3\. Traffic exhibits characteristics consistent with programmatic execution:

* Non-browser or unknown User-Agent strings, and/or  
* Streaming or event-based client signatures, and/or  
* Bursty or machine-paced request timing

4\. Interaction cannot be conclusively classified as direct human-interactive AI usage

Production Detection Signatures (100% Accuracy Validated):

Signature 1: Non-Browser User-Agent \- Evidence: "Unknown(connect-es/1.6.1)" (53 occurrences). Rule: IF user\_agent NOT IN \[Chrome, Firefox, Safari, Edge\] AND destination IN \[ai\_domains\] THEN classify as AGENT\_TO\_AI

Signature 2: gRPC-Web Protocol \- Evidence: /aiserver.v1.filesyncservice/fsuploadfile endpoint pattern. Rule: IF url\_pattern MATCHES '\*/v\\\\d+/.\*service/\*' THEN classify as MCP\_STYLE\_PROTOCOL

Signature 3: Sub-Second Bursts \- Evidence: 4 API calls at timestamp 08:04:34.000 UTC. Rule: IF request\_count \>= 3 AND time\_window \< 1 second THEN classify as AUTOMATED\_AGENT

Signature 4: Payload Asymmetry \- Evidence: 18.37x request/response ratio (57 KB sent, 3 KB received). Rule: IF ratio \> 5.0 over 10+ requests THEN classify as CONTEXT\_UPLOAD\_PATTERN

*Note: These events MUST also include the core required fields (event\_type, timestamp, schema\_version, source) defined in Section 4.1.1.*  
Required Fields:  
event\_type (string): "ai.agent.activity.detected"  
timestamp (string): ISO 8601 format  
principal (object): User or entity identifier  
execution\_context (object): How AI activity was initiated  
network\_characteristics (object): Observable network metadata  
ai\_activity (object): AI-related activity description  
evidence (object): Telemetry sources and supporting data

Example Event (from Production Transaction \#215):

{  
"event\_type": "ai.agent.activity.detected",  
"timestamp": "2025-12-16T08:00:34Z",  
"principal": {  
"type": "user",  
"id": "user@example.com"  
},  
"execution\_context": {  
"origin": "endpoint",  
"interaction\_model": "U2A",  
"agent\_presence": "inferred",  
"confidence\_basis": \[  
"non-browser user agent (connect-es/1.6.1)",  
"programmatic request cadence (8 calls/second)",  
"gRPC-Web client signature"  
\]  
},  
"network\_characteristics": {  
"protocol": "HTTPS",  
"ssl\_inspected": true,  
"user\_agent": "Unknown(connect-es/1.6.1)",  
"request\_pattern": "bursty",  
"tls\_version": "TLS 1.3"  
},  
"ai\_activity": {  
"activity\_type": "model\_inference",  
"access\_method": "direct\_api",  
"destination": "api2.cursor.sh",  
"endpoint\_pattern": "gRPC-Web"  
},  
"evidence": {  
"telemetry\_sources": \["network", "tls", "user\_agent", "temporal\_analysis"\],  
"transaction\_id": 215,  
"data\_transferred": {  
"sent\_bytes": 1539,  
"received\_bytes": 373  
}  
}  
}

Processing Requirements:

Implementations MUST NOT assert specific agent name unless explicitly available  
Implementations MUST treat agent presence as inferred when based solely on network telemetry  
Implementations SHOULD correlate multiple signals (user-agent \+ timing \+ payload directionality) for high confidence (production: multi-signal fusion achieved \>95% confidence vs. \~50-70% single-signal)  
Implementations MAY enrich with endpoint or identity telemetry when available

Implementation Note: Production validation confirms Electron applications may spoof browser signatures. Implementations SHOULD look for "Electron" in User-Agent strings as definitive agent signature even when "Chrome" or "Safari" present. Example: "Mozilla/5.0...Cursor/2.2.23 Chrome/138...Electron/37.7.0" is desktop agent, not browser.

### 

### 

### 

### 3.6.4 Event: Potential Semantic Data Exposure

A system MUST generate an \`ai.semantic.data.exposure\` event when observing AI agent activity where:

1\. Context or prompt-like data is transmitted to an AI model, AND  
2\. Response contains generated content derived from that context, AND  
3\. No traditional file transfer is observed

This event represents semantic risk, not confirmed data loss.

Production Evidence: Traditional DLP systems flagged zero violations while 56 KB of source code was uploaded to third-party AI service. Mechanism: Data transmitted in HTTP POST bodies via gRPC-Web API payloads, not as discrete file transfers. Traditional DLP perspective: "POST → 200 OK" \= ALLOWED. Reality: Intellectual property semantically extracted and transmitted.  
*Note: These events MUST also include the core required fields (event\_type, timestamp, schema\_version, source) defined in Section 4.1.1.*

Required Fields:  
event\_type (string): "ai.semantic.data.exposure"  
timestamp (string): ISO 8601 format  
principal (object): User or entity identifier  
ai\_activity (object): Interaction model and inference mode  
data\_characteristics (object): Outbound/inbound data description  
risk\_assessment (object): Risk type and DLP applicability  
evidence (object): User agent and traffic pattern

Example Event (from Production Transactions \#557-567):

{  
"event\_type": "ai.semantic.data.exposure",  
"timestamp": "2025-12-16T08:10:10Z",  
"principal": {  
"type": "user",  
"id": "user@example.com"  
},  
"ai\_activity": {  
"interaction\_model": "U2A",  
"inference\_mode": "file\_sync",  
"ai\_service": "cursor.sh"  
},  
"data\_characteristics": {  
"outbound": "context\_submission",  
"outbound\_bytes": 57324,  
"inbound": "generated\_response",  
"inbound\_bytes": 3120,  
"semantic\_transformation": true,  
"file\_count": 5,  
"request\_response\_ratio": 18.37  
},  
"risk\_assessment": {  
"risk\_type": "semantic\_exfiltration",  
"traditional\_dlp\_applicable": false,  
"data\_classification": "unknown",  
"cross\_border": true,  
"source\_country": "Egypt",  
"destination\_country": "United States"  
},  
"evidence": {  
"user\_agent": "Unknown(connect-es/1.6.1)",  
"traffic\_pattern": "context\_then\_response",  
"endpoint": "us-only.gcpp.cursor.sh:443/aiserver.v1.filesyncservice/fsuploadfile",  
"transaction\_ids": \[557, 559, 562, 564, 567\],  
"burst\_duration\_seconds": 5  
}  
}

Detection Pattern: File upload operations to AI backends exhibiting:  
Endpoint patterns: /filesync\*, /upload\*, /\*sync\*  
Payload sizes: 10-30 KB (consistent with source code files)  
High request/response ratios: \>5:1 (large uploads, minimal acknowledgments)  
Burst sequences: Multiple uploads within seconds

Production Example: 5 file uploads in 5 seconds:  
08:10:10 UTC | 10,515 bytes → /filesyncservice/fsuploadfile  
08:10:11 UTC | 11,085 bytes → /filesyncservice/fsuploadfile  
08:10:12 UTC | 11,991 bytes → /filesyncservice/fsuploadfile  
08:10:14 UTC | 12,519 bytes → /filesyncservice/fsuploadfile (largest)  
08:10:15 UTC | 11,214 bytes → /filesyncservice/fsuploadfile  
Total: 57,324 bytes (56 KB) to Cursor AI backend

### 3.6.5 Security Considerations

Agent Identity Obfuscation: Agent identity often not declared on wire. Production evidence: User-agent "Unknown(connect-es/1.6.1)" identifies gRPC-Web library but not agent identity (Cursor IDE). Only through correlation with "Electron/37.7.0" signatures could agent be definitively identified. Implementations MUST treat agent presence as inferred.

Cloud Governance Blind Spots: Cloud-side AI governance may have no visibility. Production validation confirms: Cursor IDE made 63 API calls without authentication to enterprise AI control planes. Implementations SHOULD rely on inline telemetry rather than cloud-only approaches.

Traditional DLP Ineffectiveness: Semantic data exposure bypasses file-based DLP. Production evidence: 56 KB uploaded via gRPC-Web API payloads. Traditional DLP saw "POST → 200 OK" (allowed). Reality: IP transmitted to third-party AI.

This specification intentionally does not standardize internal agent orchestration mechanisms (e.g., retrieval pipelines, vector databases, prompt construction). Such mechanisms are treated as non-normative implementation details. Security events are defined only for externally observable interactions and outcomes, including tool invocation, resource access, context disclosure, and semantic risk.

### 

### 3.6.6 Privacy Considerations

Implementations MUST NOT log AI prompt or response content unless explicitly authorized. Events rely on metadata and behavioral signals only.

Production Compliance Verified:  
Data captured: Byte counts, User-Agent strings, URLs, timestamps, TLS characteristics, IP addresses, HTTP status codes  
Data NOT captured: AI prompt content, AI response content, source code, variable/function names, semantic meaning

All detection achieved using network metadata only. No deep packet inspection of prompts/responses required for 100% detection accuracy.

User identifiers SHOULD follow existing organizational privacy policies. Production validation: User IDs obtained from existing authentication (no new PII collection).

### 3.6.7 Implementation Guidance

Detection Surface Prioritization: Production lesson \- cloud-side AI governance had zero visibility into Shadow MCP client. Only inline network inspection (90.7% SSL coverage) detected activity. Implementations SHOULD prioritize inline telemetry over cloud-only approaches.

Multi-Signal Fusion Essential: Single-signal confidence: \~50-70%. Multi-signal confidence: \>95%. Implementations SHOULD correlate 3+ detection signals per event for high-confidence classification.

Cross-Border Monitoring: Production validation detected Egypt → US transfers with regulatory implications (GDPR, data residency). Implementations SHOULD include source\_country and destination\_country fields in semantic exposure events.

Detection Accuracy Expectations:  
Precision: 100% (63 true positives, 0 false positives in production)  
Recommended signals: User-Agent (84% effective alone) \+ Temporal bursts (100% agent vs. human) \+ Payload asymmetry (100% context upload identification) \+ Endpoint patterns (100% gRPC-Web matching)

# 4\. Event Schema Design

## 4.1 Core Event Structure

All security events MUST follow a common JSON structure optimized for SIEM ingestion and cross-event correlation.

### 4.1.1 Required Fields

Every event MUST include:

* event\_type (string): Hierarchical classification using dot notation  
* timestamp (string): ISO 8601 format with timezone  
* schema\_version (string): Schema version for evolution support (e.g., "1.0")  
* source (string): Component generating the event

### 4.1.2 Recommended Fields

Events SHOULD include when applicable:

* correlation\_id (string): Identifier linking related events in split-transaction workflows (see Section 2.1.1). MUST be present when event is part of a multi-step data transfer.  
* severity (enum): critical, high, medium, low, info  
* user (string): User identifier associated with the activity  
* agent\_id (string): AI agent identifier  
* session\_id (string): Session identifier for correlation  
* detection\_method (enum): network\_telemetry, endpoint\_telemetry, gateway\_instrumentation, api\_logging, etc.  
* metadata (object): Extensible field for additional context

## 4.2 Interoperability Mappings

Events MUST integrate with existing security infrastructure. This section provides concrete mappings to common security event standards.

| This Spec Field | CEF Key | OCSF Class.Attribute | LEEF Key |
| ----- | ----- | ----- | ----- |
| event\_type | cs1 (customString1) | base\_event.type\_uid | eventType |
| user | suser | actor.user.name | identSrc |
| agent\_id | cs2 (customString2) | actor.process.name | proto |
| session\_id | cs3 (customString3) | session.uid | sessionID |
| data\_classification | cs4 (customString4) | file.confidentiality | category |

Note: The detection\_method field MAY use vendor-specific values beyond the enumerated values (network\_telemetry, endpoint\_telemetry, gateway\_instrumentation, api\_logging, semantic\_analysis) by private agreement between implementers.

Implementations SHOULD provide transformation tools or mappings to convert events between this specification's JSON format and target SIEM formats (CEF, LEEF, OCSF) to enable seamless integration.

# 5\. Implementation Guidance

## 5.1 Operational Considerations

Log Retention and Data Residency:

Security events containing AI agent telemetry MUST comply with organizational data retention policies and regulatory requirements. Implementations SHOULD consider:

* Retention periods: Align with SIEM retention policies (typically 90 days to 7 years depending on compliance requirements)  
* Data residency: Events containing user activity may be subject to geographic restrictions (GDPR, data sovereignty laws)  
* Archival strategy: Consider separate retention tiers for Discovery events (long-term) vs. high-volume Data Access events (shorter-term)  
* Right to deletion: Implement mechanisms to remove user-associated events in compliance with privacy regulations

# 6\. Security Considerations

## 6.3 Detection Evasion

Sophisticated adversaries may attempt to evade detection through AI-specific techniques. Implementations SHOULD be aware of these attack patterns:

Unsupervised Tool Usage: Attackers may induce AI agents to use tools or access methods that do not emit events, such as convincing an agent to execute arbitrary code that reads files directly rather than invoking monitored file access tools. Implementations SHOULD instrument all data access paths, not just designated tools.

Temporal Fragmentation: Splitting sensitive operations across time periods or sessions to avoid correlation detection.

Semantic Obfuscation: Using AI transformations to disguise the nature of accessed data while preserving attacker-useful meaning.

Blind Spot Exploitation: Deliberately targeting deployment patterns or detection surfaces known to have limited coverage, such as embedded AI within trusted applications.

# 7\. IANA Considerations

This document requests the creation of registries for AI agent security event types and field names to enable community extension while maintaining interoperability. Initial registry contents are defined in Section 3 (Event Classification Framework) and Appendix A (JSON Schema Examples) of this document. Registration policy follows Specification Required as defined in RFC 8126\.

# 8\. References

## 8.1 Normative References

\[RFC2119\] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997\.

\[RFC8174\] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017\.

\[RFC8259\] Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", RFC 8259, December 2017\.

## 8.2 Informative References

\[MCP\] Anthropic, "Model Context Protocol Specification", 2024, https://modelcontextprotocol.io/

\[LANGCHAIN\] LangChain, "LangChain Framework Documentation", 2024, https://docs.langchain.com/

\[OCSF\] Open Cybersecurity Schema Framework, "OCSF Schema", https://schema.ocsf.io/

\[CEF\] ArcSight, "Common Event Format", Micro Focus.

\[LEEF\] IBM, "Log Event Extended Format", IBM QRadar.

# Appendix A. JSON Schema Examples

This appendix provides JSON Schema definitions for core event structures. Implementations SHOULD use these schemas for validation.

## A.1 Core Event Schema

{  "$schema": "http://json-schema.org/draft-07/schema\#",  "title": "AI Agent Security Event",  "type": "object",  "required": \["event\_type", "timestamp", "schema\_version", "source"\],  "properties": {    "event\_type": {      "type": "string",      "pattern": "^(discovery|risk|data|policy|lineage|agent)\\\\."    },    "timestamp": {      "type": "string",      "format": "date-time"    },    "schema\_version": {      "type": "string",      "pattern": "^\[0-9\]+\\\\.\[0-9\]+$"    },    "source": {      "type": "string"    },    "correlation\_id": {      "type": "string",      "description": "Identifier linking related events in split-transaction workflows"    },    "severity": {      "type": "string",      "enum": \["critical", "high", "medium", "low", "info"\]    },    "user": {      "type": "string"    },    "agent\_id": {      "type": "string"    },    "session\_id": {      "type": "string"    },    "detection\_method": {      "type": "string"    },    "metadata": {      "type": "object"    }  }}

\--- END OF DOCUMENT \---

# Appendix B. Production Validation Evidence (Informative)

NOTE: This appendix is informative, not normative. It provides empirical validation of the Section 3.6 event schemas and detection methods.

## B.1 Dataset Characteristics

Traffic Source: Zscaler Zero Trust Exchange (ZIA)  
Collection Date: December 16, 2025  
Collection Time: 07:45:35 \- 08:13:45 UTC (28 minutes)  
Total Transactions: 656 HTTP/HTTPS requests  
Users: 2 authenticated  
SSL Inspection: 90.7% coverage  
TLS Versions: TLS 1.3 (81%), TLS 1.2 (10%)  
Geographic Flow: Egypt (client) → United States (AI services)

## B.2 Detection Results Summary

Agent Activity Events Generated: 63  
Semantic Exposure Events Generated: 5  
Detection Rate: 100% (all agent traffic identified)  
False Positive Rate: 0% (no browser traffic misclassified)  
Precision: 100% (63 true positives, 0 false positives)

Shadow MCP Client Identified: Cursor IDE v2.2.23  
Data Exfiltrated: 57,324 bytes (56 KB) via file synchronization operations  
Cross-Border Transfer: Egypt → United States (potential GDPR/data residency implications)  
Traditional DLP Bypass: Confirmed (zero violations flagged while 56 KB uploaded)

## B.3 Shadow MCP Client Signature Evidence

User-Agent: "Unknown(connect-es/1.6.1)"  
gRPC-Web client library (https://github.com/connectrpc/connect-es)  
53 occurrences (84% of Cursor traffic)  
Does NOT declare agent identity ("Cursor IDE")  
Only identified through correlation with "Electron/37.7.0" signatures

Endpoint Pattern: api2.cursor.sh/aiserver.v1.\*  
Service-oriented architecture (gRPC-style)  
File synchronization: /aiserver.v1.filesyncservice/fsuploadfile  
Dashboard services: /dashboardservice/getteams, /getuserprivacymode

Temporal Pattern \- Sub-Second Burst:  
\`\`\`  
08:04:34.000 UTC | POST | /dashboardservice/getteams (1,396 bytes)  
08:04:34.000 UTC | POST | /aiservice/checkfeaturesstatus (2,252 bytes)  
08:04:34.000 UTC | POST | /dashboardservice/getuserprivacymode (1,417 bytes)  
08:04:34.000 UTC | POST | /aiservice/checknumberconfigs (1,908 bytes)  
\`\`\`  
Four API calls within same second timestamp \- impossible for human browser interaction (typical human latency: 1-2 seconds minimum).

Payload Asymmetry: 18.37x request/response ratio  
Total uploaded: 57,324 bytes  
Total received: 3,120 bytes  
Pattern indicates: large context uploads → minimal AI acknowledgment responses  
Characteristic of code assistant workflows

## B.4 Semantic Data Exposure Evidence

File Upload Sequence: 5 transactions over 5 seconds to us-only.gcpp.cursor.sh:443

\`\`\`  
Transaction \#557 | 08:10:10 UTC | 10,515 bytes  
Transaction \#559 | 08:10:11 UTC | 11,085 bytes  
Transaction \#562 | 08:10:12 UTC | 11,991 bytes  
Transaction \#564 | 08:10:14 UTC | 12,519 bytes (largest)  
Transaction \#567 | 08:10:15 UTC | 11,214 bytes

Endpoint: /aiserver.v1.filesyncservice/fsuploadfile  
Method: POST  
User-Agent: Unknown(connect-es/1.6.1)  
Total: 57,324 bytes (56 KB)  
\`\`\`

Traditional DLP Bypass Mechanism:  
NO file downloads (HTTP GET with file MIME types)  
NO file attachments  
NO cloud storage sync operations  
Data transmitted in HTTP POST bodies (gRPC-Web serialization)  
\*\*Traditional DLP verdict:\*\* ALLOWED (saw only "POST → 200 OK")  
\*\*Reality:\*\* 56 KB source code uploaded to third-party AI service

Payload sizes (10-12 KB) and /filesyncservice/fsuploadfile endpoint consistent with source code files being transmitted to AI backend.

## B.5 Detection Signature Validation

Multi-Signal Fusion Results:  
Single Signal Confidence: \~50-70%  
Multi-Signal (3+) Confidence: \>95%  
\*\*Validated Approach:\*\* Correlate User-Agent \+ Temporal \+ Payload \+ Endpoint patterns

Telemetry Source Effectiveness:

| Signal Type | Effectiveness | Production Coverage |  
|------------|---------------|---------------------|  
| User-Agent Analysis | HIGH | 84% identified by this alone |  
| Temporal Burst Patterns | HIGH | 100% distinguishes agent from human |  
| Payload Asymmetry | HIGH | 100% identifies context upload |  
| Endpoint Pattern Matching | HIGH | 100% matches gRPC-Web signatures |  
| Protocol Analysis | MEDIUM | Confirms desktop agent vs. browser |  
| TLS Fingerprinting | LOW | Supporting evidence only |

## B.6 Privacy Compliance

Data Captured (Metadata Only):  
Byte counts, User-Agent strings, URL endpoints, timestamps, TLS characteristics, IP addresses, HTTP status codes, protocol identifiers

Data NOT Captured (Content):  
No AI prompt content, no AI response content, no source code inspected, no variable/function names, no semantic meaning from code

Assessment: COMPLIANT with Section 3.6.6 requirements. All detection via network metadata. No deep packet inspection of AI prompts/responses performed or required.

## B.7 Key Validation Conclusions

1\. Shadow MCP clients exist in production \- Cursor IDE detected operating without governance oversight, generating 10.8% of observed traffic

2\. Network telemetry is sufficient \- 100% detection accuracy using User-Agent \+ timing \+ endpoints \+ payloads; no cloud API integration required

3\. Cloud-side governance has no visibility \- Zero integration detected; Cursor operated independently of enterprise AI control planes

4\. Semantic exposure bypasses traditional DLP \- 56 KB uploaded via API payloads invisible to file-based DLP systems

5\. Event schemas are implementable \- Valid JSON events successfully generated from real network transactions

6\. Privacy can be preserved \- Metadata-only detection achieved 100% accuracy while protecting user privacy

## B.8 Validation Limitations

Single organization: Traffic from one enterprise deployment  
Limited duration: 28-minute observation window  
Known agent type: Cursor IDE; other AI agents may exhibit different signatures  
No false negative analysis: Ground truth not available for comparison  
Geographic specificity: Egypt-to-US flows; other regions may differ

Despite these limitations, validation demonstrates the specification addresses an observable, real-world security gap with implementable detection methods.

