# ORCA

**ORCA** is an open source binary analysis framework with a swappable
per-protocol analysis layer. Its first protocol layer targets QUIC. The
framework pairs a network capture and a precompiled server binary as two
views of the same server under attack, and produces a cross-domain
assessment that joins the views.

The framework is the artefact accompanying a research paper on QUIC
server resilience under denial-of-service and replay attacks. The paper
shows that under sustained flooding, the network capture alone hides
the activation of the server's defence path, and that the binary view
recovers the activation evidence. ORCA is the tool that produces both
views and joins them.

This document describes (i) the binary analysis framework, (ii) the
QUIC analysis layer built on top of the framework, and (iii) the
cross-domain assessment that joins the two.

---

## 1. The binary analysis framework

The framework's binary side is protocol-independent. It takes any
compiled server binary as input and produces a structured report of
the defence-related symbols, capabilities, and call patterns it
contains. Seven binary agents run in sequence over the binary; each
agent is a self-contained analysis stage that consumes the previous
stage's output and adds its own findings to the shared state.

### Binary agents

| Agent | Purpose |
|---|---|
| `static_analysis_agent` | Disassembles the binary and lifts to a high-level intermediate language. Produces the function table and the call graph. |
| `api_crossref_agent` | Cross-references API calls against the function table. Identifies which functions invoke which library or syscall APIs. |
| `string_threat_agent` | Extracts strings from the binary and classifies them by threat relevance (cryptographic primitives, error messages, defence names, etc.). |
| `string_crossref_agent` | Cross-references threat-relevant strings to the functions that reference them, so a defence-name string maps to the functions implementing the defence. |
| `api_clustering_agent` | Clusters API calls by semantic role. Groups functions that share the same defensive behaviour (rate limiting, validation, accounting). |
| `capabilities_agent` | Extracts behavioural capabilities from the lifted code. Identifies functions that implement defence patterns (retry token issuance, anti-amplification, anti-replay) regardless of how they are named. |
| `binary_summary_agent` | Aggregates the previous stages into a final binary mechanism census, structured as a list of declared defences with the symbol that implements each. |

The framework's design choice that distinguishes it from a standard
reverse-engineering pipeline is that the function name census runs
across the full function table *before* any decompilation budget is
allocated. The standard pattern ranks functions and decompiles only
the top N; defences that hide in low-ranked utility functions are at
risk of being missed. ORCA inverts this order so that defence presence
is decided against the full symbol surface.

The framework is protocol-independent. Replacing the QUIC analysis
layer (Section 2) with a different protocol layer reuses the same
binary side without modification.

---

## 2. The QUIC analysis layer

The QUIC layer adds a network side that runs in parallel with the
binary side. Six network agents process the packet capture and a TLS
keylog and produce a structured report of QUIC-specific traffic
features.

### Network agents

| Agent | Purpose |
|---|---|
| `pcap_ingest_agent` | Reads the packet capture and the TLS keylog. Reassembles QUIC long-header and short-header packets and keys each connection by destination connection identifier (not by IP/port pair). |
| `traffic_statistics_agent` | Computes per-flow features: connection rate, single-packet flow ratio, unidirectional-to-bidirectional ratio. The features are designed against the QUIC threat surface rather than against generic TCP statistics. |
| `quic_handshake_agent` | Reports handshake completion rate by inspecting the Initial and Handshake packet number spaces of each connection. The QUIC public header is encrypted, so transport state cannot be read from the capture without keys. |
| `attack_classification_agent` | Evaluates a precedence-ordered rule set against the feature record and emits one of four labels (NORMAL, FLOODING_DOS, SLOWLORIS_DOS, MAN_IN_THE_MIDDLE). |
| `anomaly_detection_agent` | Flags features that fall outside expected ranges, providing a side-channel signal for the cross-domain agent. |
| `quic_binary_assessment_agent` | The cross-domain agent (described in Section 3). |

### QUIC-specific design choices

The agent boundaries on the QUIC side follow the protocol's separation
of transport, cryptographic, and connection-identifier state into
distinct packet number spaces (RFC 9001 §4). Each network agent
reasons about a self-contained slice of QUIC evidence, so the
classifier can reason over a fixed feature schema without knowing how
each feature was extracted. Replacing a feature extractor (for
example, to support a new QUIC version) does not require retraining
the classifier.

The defence list against which the binary mechanism census is queried
is taken directly from RFC 9000 and RFC 9001: retry tokens, anti-
amplification, anti-replay through packet number spaces. The list is
not a generic CWE catalogue, because the resilience claim ORCA is
designed to support is specifically that the binary implements the
defences the protocol prescribes.

---

## 3. The cross-domain assessment

The cross-domain assessment joins the binary mechanism census with
the network feature record on a defence-by-defence basis. For each
canonical defence in the RFC list, the assessment checks (i) whether
the binary contains a function family that implements the defence,
(ii) whether the captured traffic shows behaviour consistent with that
defence having fired, and (iii) which specific function in the binary
the activation evidence corresponds to.

The cross-domain agent applies the same precedence-ordered rule set
as the network-only attack classifier, but it consults the binary
mechanism census in addition to the traffic features. This is where
the framework's load-bearing work happens: RFC 9000 leaves activation
thresholds (retry token issuance, rate limiting) implementation-
defined, so the gap between a defence existing in the binary and that
defence activating on the network can only be resolved by joining
both views.

The cross-domain agent is implemented as a rule-guided LLM rather
than a hand-coded rule executor. The LLM choice gives the framework
the property that adding a new defence to the mechanism census is a
prompt change rather than a code change. Non-determinism is bounded
by self-consistency voting at five queries per capture; the majority
label is reported and the five-vote distribution is recorded for
per-result audit.

---

## Repository layout

```
orca/
├── core/             orchestration, state schema, workflow dispatch,
│                     LLM provider wrapping, embedding utilities
├── correlation/      cross-domain assessment logic
├── domains/
│   ├── binary/       seven binary agents (Section 1)
│   └── network/      six network agents incl. QUIC-aware (Section 2)
├── prompts/          LLM prompts used by the agents
└── tests/            unit and integration tests
```

The `domains/` boundary is the extension point: adding a new protocol
analysis layer means adding a sibling directory under `domains/` and
wiring it into the `correlation/` cross-domain agent.

---

## Setup

ORCA is a Python package. The cross-domain assessment agent runs by
default on **OpenAI GPT-4o at temperature 0.1, top\_p 1.0**, with five
queries per capture under self-consistency voting; this is the
configuration the accompanying paper's experiments use.

```
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...
```

ORCA also supports an Anthropic backend if you set
`LLM_PROVIDER=anthropic` and `LLM_MODEL=...` in the environment, or
edit `orca/core/config.py`. The framework's prompts are decoupled from
any specific provider, so swapping backends does not require code
changes.

---

## Running the QUIC study

The dataset and reproduction inputs (PCAP captures, TLS keylogs,
server binaries, ground-truth metadata) for the accompanying paper's
findings are released separately at <ANONYMISED-DATASET-URL>.

To run the cross-domain pipeline on a single capture:

```
python -m orca.cli --binary <path-to-server-binary> \
                   --pcap   <path-to-capture.pcap> \
                   --keys   <path-to-keys.log>
```

The output is a JSON record containing:

- The binary mechanism census (defences found, defences missing,
  symbol map per defence).
- The traffic-side feature record (rates, ratios, handshake
  completion).
- The cross-domain assessment (attack label, activating function per
  declared defence, attempted-to-admitted ratio under flood).

---

## Citing

If you use ORCA in academic work, please cite the accompanying paper.
The non-anonymised citation will be linked here in the camera-ready
version.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
