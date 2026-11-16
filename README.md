# Forge

A GitHub-compatible code forge in a single Node.js file.

Forge reimplements the core of GitHub as one self-contained program: a REST API, a GraphQL API, an MCP endpoint for AI agents, and a working git server. Real git clients can clone from it and push to it. There are no dependencies at all; the git object model, the packfile reader and writer, and the pkt-line protocol framing are implemented from scratch on the Node standard library.

## Quickstart

Node 22 or newer, nothing to install:

```bash
node serve.mjs
```

The launcher boots the forge and prints its base URL and a demo token. Everything is in memory, so each run starts clean. Press Ctrl+C to stop.

## What you can do with it

**REST API (v3 style, under `/api/v3`)**

```bash
curl -H "Authorization: Bearer demo-token" http://127.0.0.1:PORT/api/v3/user
curl -H "Authorization: Bearer demo-token" -X POST http://127.0.0.1:PORT/api/v3/user/repos -d '{"name":"hello"}'
curl -H "Authorization: Bearer demo-token" http://127.0.0.1:PORT/api/v3/repos/adaiversen/hello/issues
```

Repositories, issues, labels, comments, pull requests, branches, commits, and file contents are all served with GitHub-shaped JSON, pagination headers included.

**Real git over HTTP**

```bash
git -c protocol.version=0 -c http.extraHeader="Authorization: Bearer demo-token" \
  clone http://127.0.0.1:PORT/adaiversen/hello.git
git -c http.extraHeader="Authorization: Bearer demo-token" push
```

Push, clone, fetch, and ls-remote all work against the forge's own object store. Note: fetch and clone currently run over git protocol v0, so pass `-c protocol.version=0` as shown; push works with default settings.

**GraphQL (v4 style, at `/api/graphql`)**

```graphql
{ viewer { login } }
{ repository(owner: "adaiversen", name: "hello") { nameWithOwner createdAt } }
```

**MCP (at `/mcp`)**

A Model Context Protocol endpoint exposes forge operations as agent tools, including `create_repo`, `get_repo`, `create_issue`, `list_issues`, `create_pull_request`, and `merge_pull_request`, over JSON-RPC `tools/list` and `tools/call`.

## How it works

- **One file.** `main.ts` (about 124 KB) contains the entire server: HTTP routing, the REST and GraphQL layers, the MCP endpoint, and the git transport.
- **Git from scratch.** Commits, trees, blobs, and tags are stored as content-addressed objects. Packfile generation and parsing, delta application, and pkt-line framing are implemented directly on `node:crypto` and `node:zlib`, with no git binary involved on the server side.
- **Deterministic.** No wall clock and no randomness reach stored or returned data. Timestamps tick sequentially from a fixed base and every id is a counter or a content hash, so identical request sequences produce byte-identical responses.
- **Zero dependencies.** Only the Node standard library. Node 22+ runs the TypeScript source directly.

## Layout

| File | Job |
| --- | --- |
| `main.ts` | The entire forge |
| `serve.mjs` | Local launcher: coordinator stub plus forge, one command to run |
| `LICENSE` | MIT license |

## License

MIT. See [LICENSE](LICENSE).

Built by [Magrify](https://magrify.com).
