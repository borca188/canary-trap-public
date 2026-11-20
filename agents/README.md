# Agents

Command-line AI agents we have used for project demonstrations. Each gives one of two local models
(Qwen 3.5 or GPT-OSS) two tools: one that reads documents and one that sends HTTP requests to any
URL. Ask the agent about a [honeypot document](../honeypots/README.md), and the
[endpoint](../endpoint/README.md) dashboard shows whether it followed the hidden instruction and
sent the callback request.

- **`vulnerable/`** is the baseline agent, with no defences.
- **`mitigated/`** is the same agent with prompt-injection mitigations, each behind its own
  flag. Each numbered folder fixes the flags to one combination.

> [!WARNING]
> The supplied agents are for demonstration purposes and are not production ready.
> Run them only against test documents and systems you own.

## Layout

```
agents/
├── vulnerable/
│   ├── gpt-oss/gpt-oss_http_agent.py
│   └── qwen/qwen_http_agent.py
└── mitigated/
    ├── 1_static_delimiters/      # gpt-oss_static_delimiters.py, qwen_static_delimiters.py
    ├── 2_nonce_delimiters/       # gpt-oss_nonce_delimiters.py, qwen_nonce_delimiters.py
    ├── 3_datamarking/            # gpt-oss_datamark_delimiters.py, qwen_datamark_delimiters.py
    ├── 4_sandwiching/            # gpt-oss_sandwiching.py, qwen_sandwiching.py
    ├── 5_provenance_gate/        # gpt-oss_gate.py, qwen_gate.py
    ├── 6_nonce_sandwich/         # gpt-oss_combined.py, qwen_combined.py
    └── 7_full_layered/           # gpt-oss_http_agent_injection_mitigations.py,
                                  # qwen_http_agent_injection_mitigations.py
```

Every script is a single standalone file, configured by constants near the top. The `qwen` and
`gpt-oss` copies in a folder are identical apart from `OLLAMA_MODEL` (`qwen3.5:9b` or
`gpt-oss:20b`). The mitigated scripts are all the same program with different flag settings.

## Setup

You need Python 3.10+ and [Ollama](https://ollama.com). Install the agents' packages into their own
virtualenv in `agents/` (`.venv/` is gitignored), separate from the endpoint's. Recent Ubuntu, Debian
and Homebrew Python refuse a `pip install` outside a virtualenv. Run these from the repository root,
in a different terminal from the endpoint.

Linux / macOS:

```bash
# Debian/Ubuntu need python3-venv for the venv step: sudo apt install python3-venv -y
python3 -m venv agents/.venv
source agents/.venv/bin/activate
# openai is only used by vulnerable/ (we planned to use it but ran out of time)
pip install ollama openai requests pypdf python-docx beautifulsoup4
ollama pull qwen3.5:9b
ollama pull gpt-oss:20b
```

Windows (Command Prompt):

```command prompt
py -m venv agents\.venv
agents\.venv\Scripts\activate.bat
pip install ollama openai requests pypdf python-docx beautifulsoup4
ollama pull qwen3.5:9b
ollama pull gpt-oss:20b
```

Activate the virtualenv again in each new terminal (`source agents/.venv/bin/activate`, or
`agents\.venv\Scripts\activate.bat` on Windows). Then run a script directly, for example:

```bash
python agents/vulnerable/qwen/qwen_http_agent.py
python agents/mitigated/7_full_layered/gpt-oss_http_agent_injection_mitigations.py
```

## Using an agent

Type at the `you>` prompt. Mention a file path and the agent can read it; mention a URL and it can
fetch it. For example: `Summarise /home/me/tests/blogAF.html`. Press Ctrl+C or Ctrl+D to quit.

`/reset` starts a new conversation in the mitigated agents, keeping the configured mitigations and
clearing the gate's record of untrusted content. In the vulnerable agent, `/reset` currently keeps
the first message of the old conversation, so restart the script for a clean run.

The startup banner prints the model and every setting that affects results. Lines in the output
mean:

| Line | Meaning |
|---|---|
| `[calling …]` | The model called a tool, with the arguments it chose |
| `[HTTP …]`, `[document read: …]`, `[tool error: …]` | The result of that call |
| `[!]` | This turn is not a valid result: a document or response was truncated, `.docx` text was missed, the context is nearly full, or the tool-round limit was reached |
| `[i]` | Housekeeping, such as an earlier copy of a re-read file being replaced with a short note |
| `[gate]` | Mitigated only: a request the gate stopped because untrusted content had arrived, and whether it was then sent. A refused request never reaches the endpoint, so it does not appear on the dashboard |
| `[marker]` | Mitigated only: a source contained text shaped like the delimiter markers, an attempt to forge a boundary |
| `[sandwich]` | Mitigated only: the reminder was added before the next model call |

## Tools

**`read_document(path)`** reads a local `.txt`, `.md`, `.csv`, `.log`, `.json`, `.pdf`, `.docx`,
`.html` or `.htm` file and returns its text plus any links found in it.

- **HTML** is reduced to visible text. Scripts, styles and attributes are dropped, apart from
  link targets, which go in the link list. An instruction hidden in an attribute is never seen
  this way, which is why the frisbee catalogue honeypot must be fetched over HTTP instead.
- **`.docx`** files also include tables, text boxes, content controls, headers, footers, footnotes,
  endnotes and comments when `DOCX_FULL_EXTRACTION` is on. With it off, only body paragraphs are read, as a
  common basic loader would.

**`http_request(url, method, headers, params, body, timeout)`** sends any method (GET, POST, PUT,
PATCH, DELETE, HEAD or OPTIONS) to any URL and returns the status, headers and body. HTML comes back
raw, markup included.

If the same file or URL is read again, the earlier copy in the conversation is replaced with a short
note, so the context holds one copy of each source.

## Settings

Shared by every script:

| Constant | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | `qwen3.5:9b` or `gpt-oss:20b` | Ollama model to run |
| `DOCUMENT_MAX_CHARS` | `100_000` | Cap on text returned from a file. Keep it above your largest test document |
| `HTTP_MAX_CHARS` | `40_000` | Cap on an HTTP response body |
| `DOCX_FULL_EXTRACTION` | `True` | Read the extra `.docx` parts listed above |
| `NUM_CTX` | `40960` | Ollama context window. Too small and Ollama silently drops the oldest messages |
| `CONTEXT_WARN_FRACTION` | `0.85` | Print `[!]` when the estimated prompt passes this share of `NUM_CTX` |
| `MAX_TOOL_ROUNDS` | `10` | Tool-call rounds allowed per turn |
| `TEMPERATURE`, `SEED` | `None` | Decoding settings; `None` uses the backend default |
| `DEFAULT_TIMEOUT` | `15.0` | HTTP timeout in seconds |

The vulnerable agent can also call a model through the OpenAI API. Set `PROVIDER = "openai"`, set
`OPENAI_MODEL` to the model you are testing, and export `OPENAI_API_KEY`. The mitigated agents run
through Ollama only.

> [!NOTE]
> The OpenAI option is untested. The team planned to test it with a team member's own API key but
> ran out of time, so only the Ollama models were tested.

## Mitigations

| Folder | `DELIMITER_MODE` | `SANDWICH` | `PROVENANCE_GATE` |
|---|---|---|---|
| `1_static_delimiters/` | `static` | off | off |
| `2_nonce_delimiters/` | `nonce` | off | off |
| `3_datamarking/` | `datamark` | off | off |
| `4_sandwiching/` | `off` | on | off |
| `5_provenance_gate/` | `off` | off | on (`block`) |
| `6_nonce_sandwich/` | `nonce` | on | off |
| `7_full_layered/` | `nonce` | on | on (`block`) |

To try another combination, change the flags in any mitigated script.

### Delimiters (`DELIMITER_MODE`)

A system prompt tells the model that tool results are untrusted data, and each result is marked to
match. This labels the data; the model can still choose to obey an instruction inside it.

- **`off`**: raw tool results and no system prompt.
- **`static`**: every result is wrapped in fixed `<<<BEGIN/END_UNTRUSTED_EXTERNAL_CONTENT>>>`
  markers. A document can forge the end marker, so this is kept as a comparison point.
- **`nonce`**: the markers carry a fresh random id for every result, so a document cannot predict
  them. Marker-like text in the content is removed and reported with `[marker]`.
- **`datamark`**: a random 3-symbol marker, chosen per result, replaces every gap between words, for
  example `the^~|report^~|says`. It roughly doubles the tokens, so check `NUM_CTX`, and a small
  model may answer less accurately, so also test it on a clean document.

### Sandwiching (`SANDWICH`)

After a round of tool calls that brought in external content, the agent adds a short reminder that
quotes the user's latest request, so the last thing the model reads before acting is the user's
instruction. Only the newest reminder is kept.

`SANDWICH_ROLE` sets whether the reminder is sent as a `system` (default) or `user` message. Some
chat templates drop system messages after the first one, which would silently turn this off. Check
with `ollama show <model> --template`, and use `user` if in doubt.

### Provenance gate (`PROVENANCE_GATE`)

Enforced by the script, not the model. Once a document or HTTP response is in the conversation, a
request is sent only if it is a GET or HEAD, with no headers or body, to a URL the user typed
exactly. Anything else is held:

- **`ask`**: the agent asks you whether to send it.
- **`block`**: it is refused without asking, so runs can be left unattended.

The gate looks at the whole conversation rather than each value's source, so a POST you asked for
yourself is also held once a document has been read. File reads are never gated.

The docstring at the top of each mitigated script describes every mitigation in full, with its
sources.
