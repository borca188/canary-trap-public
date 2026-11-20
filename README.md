# Canary Trap

Canary Trap is used to detect unintended AI agent behaviour caused by concealed instructions inside
external documents. Honeypot documents carry a unique callback URL alongside hidden
instructions telling an agent to fetch it. If an agent reads the document and follows those
instructions, the request is logged and appears on a dashboard as evidence.

```
Honeypot document -> AI agent follows the unique URL -> endpoint validates the token
-> event is logged -> event appears on the dashboard
```

The repository holds all three parts of a test: the logging endpoint, the honeypot documents, and
test agents that read those documents with and without prompt-injection mitigations.

Built for ICT302 by Team Hivemind at Murdoch University.

## Who this project is for

- **Testers and security researchers** who want to check whether an AI agent or tool acts on
  instructions hidden in the documents it reads.
- **The IT09 team and future maintainers** working on the endpoint, honeypot documents or test
  agents.

Canary Trap is a prototype for a single user on a trusted machine or network. The dashboard has
no login, so it should not be exposed publicly; only the callback URLs are meant to be reachable from
the internet if exposed. It is not designed for production use in its current state.

## Repository structure

```
canary-trap/
├── endpoint/          # Flask + SQLite logging endpoint and dashboard
│   ├── routes/        # Callback, JSON API and dashboard routes
│   ├── static/        # Stylesheet and logo
│   └── templates/     # Jinja2 templates for the dashboard
├── honeypots/         # Three honeypot documents, four injection variants of each
├── agents/            # Test agents that read documents and send HTTP requests
│   ├── vulnerable/    # Baseline agents with no mitigations
│   └── mitigated/     # Agents with mitigations, one folder per configuration
├── LICENSE            # Apache License 2.0
└── README.md
```

## What each folder contains

### `endpoint/`

The working application. It issues unique callback URLs, records any request that hits one, and
provides a dashboard, JSON API and CSV export for reviewing the results. Setup instructions are in
the [endpoint README](endpoint/README.md).

| Path | Contents |
|---|---|
| `app.py` | Flask app factory and blueprint registration |
| `config.py` | Database paths, display timezone and settings read from environment variables |
| `db.py` | SQLite connection helper and database initialisation |
| `schema.sql` | Definitions for the `tokens`, `events` and `suppressed_events` tables |
| `tokens.py` | Token generation, lookup and listing |
| `events.py` | Event logging, querying and rate limiting |
| `security.py` | Host allowlist, CSRF checks and session secret key |
| `requirements.txt` | Python dependencies |
| `routes/honeypot.py` | Callback URLs and custom-path redirects |
| `routes/api.py` | JSON API for creating and listing tokens and their events |
| `routes/dashboard.py` | Dashboard pages and CSV export |
| `templates/` | Jinja2 templates for the dashboard and token detail pages |
| `static/` | Stylesheet and logo |

Running the app also creates `instance/`, which holds the SQLite database and session secret key.
This folder is gitignored, as is the local virtualenv (`.venv/`).

### `honeypots/`

Three bait documents, each hiding one instruction that tells the reader to send a GET request to a
callback URL.

| Folder | Document | Where the instruction is hidden |
|---|---|---|
| `Annual-Financial-Report-2025 (.docx)/` | Annual financial report | 1 pt white text after Table 7 |
| `Open Field Catalogue (frisbee-catalogue.html)/` | Frisbee product catalogue | An HTML attribute on one product image |
| `Operation Low Tide (blog.html)/` | Threat-research blog post | A `display: none` block after the overview |

Each document comes in four variants, named by the suffix on the filename. They are identical
except for how the instruction is worded, so results can be compared across techniques:

| Suffix | Technique                         | How the instruction is worded                                                                                     |
| ------ | --------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `AF`   | Authoritative Context Framing     | As a publisher's document-processing requirement                                                                  |
| `APD`  | Algorithmic Payload Decomposition | Split up among colour names in a word list, with a request to remove the colours and run the command that is left |
| `RP`   | Role-Play Prompting               | As a role for the agent to take on, such as a link-verification technician                                        |
| `TR`   | Trigger-Activated Rule Addition   | As a rule that applies only if the user asks for a summary                                                        |

The callback URLs in these files point at the team's test VM (`http://192.168.217.132:5000`).
Before testing against your own endpoint, create a token on its dashboard and replace the URL in the
document with the new one.

### `agents/`

Command-line chat agents for running the tests. Each gives a model two tools, `read_document` for
local files (.txt, .md, .csv, .pdf, .docx, .html and more) and `http_request` for any URL. Point one
at a honeypot document and the endpoint shows whether it sent the callback request.

Every script is standalone and is configured by constants at the top of the file. Each comes in two
copies that differ only in the model, `qwen3.5:9b` or `gpt-oss:20b`, both served through Ollama.

- **`vulnerable/`**: the baseline agent, with no mitigations. It can also call a model through the
  OpenAI API (set `PROVIDER = "openai"` and export `OPENAI_API_KEY`), but this option is untested:
  the team planned to test it with a team member's own API key but ran out of time.
- **`mitigated/`**: the same agent with three mitigations, each behind its own flag. Each numbered
  folder fixes the flags to one configuration, so each mitigation can be measured alone and in
  combination.

| Folder | `DELIMITER_MODE` | `SANDWICH` | `PROVENANCE_GATE` |
|---|---|---|---|
| `1_static_delimiters/` | `static` | off | off |
| `2_nonce_delimiters/` | `nonce` | off | off |
| `3_datamarking/` | `datamark` | off | off |
| `4_sandwiching/` | `off` | on | off |
| `5_provenance_gate/` | `off` | off | on (`block`) |
| `6_nonce_sandwich/` | `nonce` | on | off |
| `7_full_layered/` | `nonce` | on | on (`block`) |

- **Delimiters** label every tool result as untrusted data: with fixed markers (`static`), with
  markers carrying a fresh random id per result (`nonce`), or with a random marker between every
  word (`datamark`).
- **Sandwiching** adds a reminder of the user's latest request after external content arrives, so
  the last thing the model reads before acting is the user's instruction.
- **The provenance gate** acts as a policy rather than a system-level prompt. Treats external sources
  as "tainted". Requests are either held for the user's approval (`ask`) or refused (`block`).

The docstring at the top of each mitigated script describes the mitigations in full, with sources.

To run an agent (Python 3.10+ and [Ollama](https://ollama.com) required), install its packages into
a virtualenv in `agents/`, from the repository root. The [agents README](agents/README.md#setup) has
the Windows commands.

```bash
python3 -m venv agents/.venv
source agents/.venv/bin/activate
pip install ollama openai requests pypdf python-docx beautifulsoup4   # openai is only used by vulnerable/
ollama pull qwen3.5:9b                                               # or gpt-oss:20b
python agents/vulnerable/qwen/qwen_http_agent.py
```
Provide one of the honeypot documents either by path or URL. Ask for a summary and wait for its output.
You should be able to observe whether the agent is calling its tools, meaning you can directly confirm
whether the agent is attempting to read the document or has sent an HTTP request. For successful test runs,
you should be able to observe the agent sending a request to the token URL. Check the dashboard after
the agent has completed the user's request to identify successful callbacks from the agent.

## License

Released under the [Apache License 2.0](LICENSE).
