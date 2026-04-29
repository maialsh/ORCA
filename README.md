# ORCA

ORCA is an open source binary analysis framework with a QUIC analysis layer.

It pairs a network capture and a precompiled QUIC server binary as evidence
of the same server under attack, and produces:

- A binary mechanism census against the canonical defences specified in
  RFC 9000 and RFC 9001.
- A traffic side feature record (per flow rate, single packet ratio,
  unidirectional to bidirectional ratio, handshake completion).
- A cross domain assessment that joins the two views and names the
  activating defence function per implementation.

## Repository layout

```
orca/
├── core/             orchestration, state, workflow dispatch
├── correlation/      cross domain assessment
├── domains/
│   ├── binary/       7 binary analysis agents
│   └── network/      6 network analysis agents (QUIC aware)
├── prompts/          LLM prompts used by the agents
└── tests/
```

## Setup

```
pip install -r requirements.txt   # or: pipenv install
```

Set your OpenAI API key:

```
export OPENAI_API_KEY=sk-...
```

## Running the QUIC study

The dataset, ground truth, and reproduction script for the paper's flood
defence activation finding and MitM intensity sweep are released
separately at <ANONYMISED-DATASET-URL>.

```
python -m orca.cli --binary <path-to-server-binary> \
                   --pcap   <path-to-capture.pcap> \
                   --keys   <path-to-keys.log>
```

The output is a JSON record per capture with the activating defence
function name, the attempted-to-admitted ratio, and the cross domain
classification.

## Citing

If you use ORCA in academic work, please cite the accompanying paper.

## License

See [LICENSE](LICENSE).
