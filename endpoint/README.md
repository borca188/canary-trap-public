# Logging Dashboard/Endpoint

A minimal Flask + SQLite application for detecting **indirect prompt injection**: it issues
unique, secret callback URLs to embed inside "honeypot" documents, and records any request that
hits one of those URLs. If an AI agent reads a honeypot document and, as a result of injected
instructions, fetches the embedded URL, that fetch is captured as evidence.

```
Honeypot document -> AI/agent follows unique URL -> Flask endpoint receives request
-> token is validated -> event is logged -> event appears on dashboard
```

This project only implements the detection backend (token issuance, callback capture, storage,
dashboard, export). Creating the actual honeypot documents (PDF/DOCX) that embed the callback
URLs is a separate, manual step.

## Requirements

- Python 3.10+ (developed against 3.14)
- Flask (see `requirements.txt`)
- Linux, macOS or Windows. Commands below are for bash; Windows equivalents (PowerShell) are
  given where they differ.

## Installation

Create a virtualenv in `endpoint/` and install the dependencies into it (`.venv/` is gitignored, so
a fresh clone has none).

Linux / macOS:

```bash
# Install Python if needed (python3-venv is required for the venv step on Debian/Ubuntu):
#   Debian/Ubuntu:    sudo apt install python3 python3-venv -y (or go to https://www.python.org/downloads/)
#   macOS (Homebrew): brew install python (or go to https://www.python.org/downloads/)
cd endpoint
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (Command Prompt):

```command prompt
# Install Python if needed:
#   winget install 9NQ7512CXL7T (or go to https://www.python.org/downloads/)
cd endpoint
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Running

From `endpoint/`, with the virtualenv active (same command on every OS):

```bash
flask --app app run --port=5000
```

The app starts on `http://127.0.0.1:5000/` and creates `instance/honeypot.db` automatically on
first run. It binds to localhost only, which is what you want: the dashboard has no login, so it
should not be reachable from other machines. If you must listen on all interfaces, add
`--host=0.0.0.0`, and do so only on a trusted network: anyone who can reach the machine can then
use the dashboard. To open the dashboard from another machine, also add this machine's address to
`DASHBOARD_HOSTS` (see [Configuration](#configuration)); the dashboard returns `404 Not Found` on
any address not in that list.

## Configuration

The app reads its settings from environment variables when it starts. All of them are optional, and
the defaults suit one operator using the dashboard on the same machine.

| Variable | Default | What it does |
|---|---|---|
| `PUBLIC_BASE_URL` | Unset: URLs use the address the dashboard was opened on | The address used in the callback and custom URLs that the dashboard and API show: a scheme and host with an optional port and no path, for example `https://trap.example.com`. Set it when agents reach the endpoint at a different address than the one you open the dashboard on. It only changes the URLs shown, not which requests are logged. |
| `DASHBOARD_HOSTS` | `localhost,127.0.0.1,::1` | Comma-separated hostnames or IP addresses, without ports, that the dashboard and API answer on. Any other host gets `404 Not Found`. The value replaces the whole list, so include the defaults you still use. Callback URLs answer on any host and ignore this setting. |
| `TRUSTED_PROXY_HOPS` | `0` | The number of proxies in front of the app, such as a tunnel or reverse proxy, whose `X-Forwarded-For` header is trusted for the logged IP address. With `0`, every hit that comes through a proxy is logged with the proxy's address. Only raise it when a proxy really is in front of the app: otherwise anyone can fake their logged IP by sending that header. |
| `SESSION_COOKIE_SECURE` | Off | Set it to `1` when the dashboard is served over HTTPS, so the browser only sends the session cookie over HTTPS. Leave it off when the dashboard is opened over plain `http://`: the browser may not send the cookie, and the dashboard's forms are then rejected. |
| `SECRET_KEY` | A random key saved as `secret_key` next to the database | The key that signs the dashboard's session cookie. The generated key is kept across restarts, so set this only if you want to manage the key yourself. |
| `HONEYPOT_DB` | `instance/honeypot.db` | The path of the SQLite database. Its folder is created if it doesn't exist. |

### Setting a variable

Set variables in the terminal you start the app from, before running `flask`, and restart the app
after changing one. A variable set this way lasts until the terminal is closed.

Linux / macOS:

```bash
export PUBLIC_BASE_URL=https://trap.example.com
flask --app app run --port=5000
```

Windows (Command Prompt):

```command prompt
set PUBLIC_BASE_URL=https://trap.example.com
flask --app app run --port=5000
```

If `PUBLIC_BASE_URL`, `DASHBOARD_HOSTS` or `TRUSTED_PROXY_HOPS` has an invalid value, the app stops
at startup with an error saying what is wrong.

### Checking the values

To see the values the app will use, defaults included, run this from `endpoint/` in the terminal
you start the app from (Linux / macOS). It reads `config.py` the same way the app does, without
starting it, and shows only whether `SECRET_KEY` is set, never its value:

```bash
.venv/bin/python -c "
import os, config
print('PUBLIC_BASE_URL      ', config.PUBLIC_BASE_URL or '(unset: uses the dashboard address)')
print('DASHBOARD_HOSTS      ', ','.join(sorted(config.DASHBOARD_HOSTS)))
print('TRUSTED_PROXY_HOPS   ', config.TRUSTED_PROXY_HOPS)
print('SESSION_COOKIE_SECURE', config.SESSION_COOKIE_SECURE)
print('SECRET_KEY           ', 'set' if os.environ.get('SECRET_KEY') else '(unset: uses instance/secret_key)')
print('HONEYPOT_DB          ', config.DATABASE_PATH)
"
```

A running app keeps the values it started with, so this shows what it uses only if nothing has
changed since it was started.

## Usage

A test has three steps: create a token for a honeypot document, embed the token's callback URL in
that document, then check whether an agent fetched it. Everything is done from the dashboard at
`http://127.0.0.1:5000/`.

### 1. Create a token

Under **Create Honeypot Token**, enter a **Document reference** (a label such as `resume_v1.pdf`)
and click **Create Token**. Copy the **Callback URL** it shows and put it in the honeypot document,
next to the hidden instruction that tells an agent to fetch it (see the
[honeypots README](../honeypots/README.md)).

About the URL:

- **Path.** Each token gets a path made of a random ordinary-looking folder (`assets`, `media`,
  `resources`, `images`, `files`, `docs`, `downloads` or `content`) followed by the token ID.
  `/token/<token_id>` also works for every token.
- **Custom path (optional).** Fill in **Custom URL path** (for example `products/line-finder`) to
  also get a **Custom URL** that redirects (302) to the callback URL. The callback logs the hit,
  not the redirect. Use letters, digits, `-`, `_`, `.` and `/` only. Each path can belong to only
  one token (case is ignored), and it can't start with a segment the app uses itself (`token`,
  `tokens`, `api`, `static`, `export`, `events`, `admin`, `favicon.ico`, `robots.txt`).
- **Host.** The URL uses the address you opened the dashboard on. The agent must be able to
  reach that address. If agents reach the endpoint at a different public address, set
  `PUBLIC_BASE_URL` (see [Configuration](#configuration)) before starting the app; the dashboard
  then shows URLs at that address.

### 2. What a callback records

When an agent fetches the URL, the endpoint returns a 1x1 transparent GIF, so the URL looks like an
ordinary tracking pixel. It logs the timestamp, IP address, User-Agent, HTTP method and path. An
unknown or deleted token returns `404 Not Found` and nothing is logged.

Each IP address is recorded at most 30 times per minute per token. Extra hits still get the GIF,
but they are only counted, and the dashboard shows how many were dropped.

### 3. Review hits

The dashboard shows **Tokens Created**, **Callbacks Recorded** and a **Recent Callback Activity**
table (newest first, up to 100 rows). Click a row to see the event's full details. Click a token
to open its page, which lists every event for that token.

- **Filter:** pick a field (Document reference, Token ID, IP address, User-Agent or Request path),
  type part of a value and press **Search Events**. Each search becomes a chip. Chips on different
  fields must all match; chips on the same field match any of them. **Date & Time** limits events
  to a preset or custom range in Perth time (end dates are inclusive). Filters are applied before
  the 100-row limit and are kept in the URL, so a filtered view can be bookmarked.
- **Archive:** tick events and click **Archive selected** to hide them from the default view
  (**Undo** reverses it). **Show archived** lists archived events; **Restore selected** brings
  them back. Nothing is deleted.
- **Delete a token:** **Delete** in the **Created Tokens** table deactivates the token. Its URLs
  return 404 from then on, but its events stay, and its paths can't be reused by another token.

### 4. Export results

**Export CSV** downloads the events that match the current filters, and **Export selected**
downloads only the ticked rows. **Export options** lets you choose CSV or JSON, local or UTC
timestamps, the columns, a single document, and whether archived events are included.

Values that start with `=`, `+`, `-` or `@` get a leading `'` in the CSV. The User-Agent and path
come from whoever fetched the URL, and the `'` stops a spreadsheet from running them as formulas.

## Running a test

The testing process involves exposing an AI agent to a honeypot document containing a concealed
prompt-injection instruction and observing whether the agent sends an HTTP GET request to the Canary
Trap endpoint.

1. **Start the logging endpoint.** Follow the instructions in [Running](#running) to start the
   Flask application and access the dashboard.

2. **Prepare the honeypot document.** Select one of the three honeypot documents and its desired
   prompt-injection variant (`AF`, `APD`, `RP` or `TR`). Ensure the embedded callback URL points to
   a valid token created through the dashboard.

3. **Select an AI agent.** Navigate to the [`agents/`](../agents/) directory and choose a vulnerable
   or mitigated agent script. Configure the model and any required settings before running it.

4. **Run the AI agent.** Start the selected Python script and provide a prompt asking the agent to
   read or summarise the honeypot document. The catalogue requires the agent to retrieve raw HTML to
   encounter the concealed instruction.

5. **Observe the agent's behaviour.** Review the terminal output to determine whether the agent
   attempted to follow the concealed instruction, including whether a mitigation blocked the
   request.

6. **Review the dashboard.** Check for a recorded callback associated with the document's token. A
   recorded callback indicates that the endpoint received a request to the embedded URL.

7. **Record the testing results.** Document the model, honeypot document, injection technique,
   mitigation configuration and outcome. Repeat the process as required for each testing
   configuration.

A callback alone does not prove that an AI model followed an injected instruction. The recorded
event should be compared with the agent's terminal output to determine whether the request resulted
from the injection.

## Known limitations and future work

This is a prototype built for a single operator on a trusted machine or network. Before it is used
for anything beyond that, the items below should be done, roughly in this order.

1. **Keep the dashboard private.** Authentication is out of scope for this project at the
   client's request, so the dashboard and API have no login: anyone who can reach port 5000 can read
   the evidence and delete tokens. The Host allowlist and CSRF checks only stop *other websites*
   from driving the operator's browser. Keep the dashboard on `localhost` (or an SSH tunnel) and let
   only the callback paths through any public tunnel.
2. **Run under a production server** (gunicorn behind the tunnel or a reverse proxy, packaged with
   Docker) instead of Flask's development server.
3. **Serve over HTTPS** when the dashboard leaves the machine, and set `SESSION_COOKIE_SECURE=1`.
4. **Limit request body size** (`MAX_CONTENT_LENGTH`).
5. **Treat events as indicators, not proof.** Callback URLs are public by design, so anyone holding
   one can fake a hit; rate limiting only bounds the damage.
