// github-core-clone-01: a GitHub-compatible git forge in one file.
//
// Surfaces: REST v3 under /api/v3, git smart HTTP at /{owner}/{repo}.git
// (upload-pack protocol v2 + v0, receive-pack v0), plus minimal GraphQL/MCP
// stubs that later work fleshes out. Node standard library only; the git
// object model, packfile reader/writer and pkt-line framing are implemented
// here directly on node:crypto / node:zlib.
//
// Determinism: no wall clock and no randomness reach stored or returned
// data. Timestamps derive from $MAKEFUN_TRIAL_NOW plus a sequential tick;
// every id is a sequential counter or a content hash.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants and deterministic time

const OWNER = 'adaiversen';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0'.repeat(40);

function trialBaseSec(): number {
  const raw = (process.env.MAKEFUN_TRIAL_NOW ?? '').trim();
  if (raw !== '') {
    const parsed = Date.parse(raw);
    if (!Number.isNaN(parsed)) return Math.floor(parsed / 1000);
    if (/^\d+$/.test(raw)) {
      const n = Number(raw);
      return n > 10_000_000_000 ? Math.floor(n / 1000) : n;
    }
  }
  return 1_735_689_600; // 2025-01-01T00:00:00Z
}
const BASE_SEC = trialBaseSec();
let tick = 0;
/** The next deterministic timestamp, seconds since the epoch. */
function nextSec(): number {
  tick += 1;
  return BASE_SEC + tick;
}
function isoOf(sec: number): string {
  return new Date(sec * 1000).toISOString();
}
let requestSeq = 0;
function nextRequestId(): string {
  requestSeq += 1;
  return `forge-${requestSeq}`;
}

// ---------------------------------------------------------------------------
// git object model

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('malformed tree object');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: TreeEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of [...entries].sort(compareTreeEntries)) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const view: CommitView = { tree: '', parents: [], author: '', committer: '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'tree') view.tree = value;
    else if (key === 'parent') view.parents.push(value);
    else if (key === 'author') view.author = value;
    else if (key === 'committer') view.committer = value;
  }
  return view;
}

function parseTagTarget(data: Buffer): string {
  for (const line of data.subarray(0, data.indexOf('\n\n') < 0 ? data.length : data.indexOf('\n\n')).toString('utf8').split('\n')) {
    if (line.startsWith('object ')) return line.slice(7).trim();
  }
  return '';
}

const IDENT = `${OWNER} <${OWNER}@example.invalid>`;

function buildCommitData(fields: { tree: string; parents: string[]; message: string; sec: number }): Buffer {
  const who = `${IDENT} ${fields.sec} +0000`;
  const lines = [`tree ${fields.tree}`];
  for (const parent of fields.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  const message = fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

/** Every object reachable from the roots; missing objects are skipped. */
function collectReachable(store: Map<string, GitObj>, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = store.get(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      queue.push(commit.tree, ...commit.parents);
    } else if (obj.type === 'tag') {
      const target = parseTagTarget(obj.data);
      if (target !== '') queue.push(target);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) if (entry.mode !== '160000') queue.push(entry.oid);
    }
  }
  return seen;
}

function isAncestor(store: Map<string, GitObj>, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (oid === ancestor) return true;
    const obj = store.get(oid);
    if (obj !== undefined && obj.type === 'commit') queue.push(...parseCommit(obj.data).parents);
  }
  return false;
}

/** Ancestor set of a commit with BFS depths, for merge-base computation. */
function ancestorDepths(store: Map<string, GitObj>, tip: string): Map<string, number> {
  const depths = new Map<string, number>([[tip, 0]]);
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    const depth = depths.get(oid) as number;
    const obj = store.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (!depths.has(parent)) {
        depths.set(parent, depth + 1);
        queue.push(parent);
      }
    }
  }
  return depths;
}

function mergeBase(store: Map<string, GitObj>, a: string, b: string): string | null {
  const depthsA = ancestorDepths(store, a);
  const depthsB = ancestorDepths(store, b);
  let best: string | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (const [oid, depth] of depthsA) {
    const other = depthsB.get(oid);
    if (other !== undefined && depth + other < bestScore) {
      bestScore = depth + other;
      best = oid;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// packfiles

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(writePackObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] as number;
      offset += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copyOffset += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          copySize += (delta[offset] as number) * 2 ** shift;
          offset += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta produced the wrong size');
  return out;
}

interface RawPackEntry {
  offset: number;
  typeCode: number;
  data: Buffer;
  baseOffset: number;
  baseOid: string;
}

/** Read a packfile, resolving ofs-delta and ref-delta entries (thin packs use `resolveBase`). */
function readPack(pack: Buffer, resolveBase: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const raw: RawPackEntry[] = [];
  const byOffset = new Map<number, RawPackEntry>();
  let offset = 12;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    let byte = pack[offset] as number;
    offset += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset] as number;
      offset += 1;
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOffset = -1;
    let baseOid = '';
    if (typeCode === 6) {
      let b = pack[offset] as number;
      offset += 1;
      let value = b & 0x7f;
      while ((b & 0x80) !== 0) {
        b = pack[offset] as number;
        offset += 1;
        value = (value + 1) * 128 + (b & 0x7f);
      }
      baseOffset = entryOffset - value;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== size) throw new Error('pack entry size mismatch');
    offset = inflated.next;
    const entry: RawPackEntry = { offset: entryOffset, typeCode, data: inflated.data, baseOffset, baseOid };
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolved = new Map<string, GitObj>();
  const byEntry = new Map<RawPackEntry, GitObj>();
  const resolveEntry = (entry: RawPackEntry, guard: Set<number>): GitObj => {
    const cached = byEntry.get(entry);
    if (cached !== undefined) return cached;
    if (guard.has(entry.offset)) throw new Error('delta cycle');
    guard.add(entry.offset);
    let obj: GitObj;
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObj | undefined;
      if (entry.typeCode === 6) {
        const baseEntry = byOffset.get(entry.baseOffset);
        if (baseEntry === undefined) throw new Error('ofs-delta base missing');
        base = resolveEntry(baseEntry, guard);
      } else {
        base = resolved.get(entry.baseOid);
        if (base === undefined) {
          for (const candidate of raw) {
            if (candidate.typeCode === 6 || candidate.typeCode === 7) continue;
            const plain = resolveEntry(candidate, guard);
            if (hashObject(plain.type, plain.data) === entry.baseOid) {
              base = plain;
              break;
            }
          }
        }
        if (base === undefined) base = resolveBase(entry.baseOid);
        if (base === undefined) throw new Error('ref-delta base missing');
      }
      obj = { type: base.type, data: applyDelta(base.data, entry.data) };
    } else {
      const type = CODE_TYPE[entry.typeCode];
      if (type === undefined) throw new Error(`unknown pack type ${entry.typeCode}`);
      obj = { type, data: entry.data };
    }
    guard.delete(entry.offset);
    byEntry.set(entry, obj);
    resolved.set(hashObject(obj.type, obj.data), obj);
    return obj;
  };
  for (const entry of raw) resolveEntry(entry, new Set());
  return resolved;
}

// ---------------------------------------------------------------------------
// pkt-line framing

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.from((data.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Packet = Buffer | 'flush' | 'delim';

/** Decode a complete pkt-line stream; trailing raw bytes (a pack) come back in `rest`. */
function decodePackets(buffer: Buffer): { packets: Packet[]; rest: Buffer } {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      packets.push('flush');
      offset += 4;
      // A pack may follow the command flush of a push; it starts with "PACK".
      if (buffer.subarray(offset, offset + 4).toString('ascii') === 'PACK') break;
      continue;
    }
    if (length === 1) {
      packets.push('delim');
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push('flush');
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buffer.length) break;
    packets.push(buffer.subarray(offset + 4, offset + length));
    offset += length;
  }
  return { packets, rest: buffer.subarray(offset) };
}

function packetLines(packets: Packet[]): string[] {
  const lines: string[] = [];
  for (const packet of packets) if (Buffer.isBuffer(packet)) lines.push(packet.toString('utf8').replace(/\n$/, ''));
  return lines;
}

// ---------------------------------------------------------------------------
// the store

interface LabelRec {
  id: number;
  name: string;
  color: string;
  description: string | null;
}
interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: string;
  labels: string[];
  createdSec: number;
  updatedSec: number;
  closedSec: number | null;
}
interface CommentRec {
  id: number;
  issueNumber: number;
  body: string;
  createdSec: number;
}
interface PullRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: string;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedSec: number | null;
  mergeCommitSha: string | null;
  createdSec: number;
  updatedSec: number;
}
interface Repo {
  id: number;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSec: number;
  updatedSec: number;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  labels: Map<string, LabelRec>;
  issues: Map<number, IssueRec>;
  comments: CommentRec[];
  pulls: Map<number, PullRec>;
  nextNumber: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 1;
let nextIssueId = 1;
let nextCommentId = 1;
let nextLabelId = 1;
let nextPullId = 1;

function createRepoRec(name: string, description: string, isPrivate: boolean, defaultBranch: string): Repo {
  const sec = nextSec();
  const repo: Repo = {
    id: nextRepoId,
    name,
    description,
    isPrivate,
    defaultBranch,
    createdSec: sec,
    updatedSec: sec,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    comments: [],
    pulls: new Map(),
    nextNumber: 1,
  };
  nextRepoId += 1;
  repos.set(name, repo);
  return repo;
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function branchRef(name: string): string {
  return `refs/heads/${name}`;
}

function tipOf(repo: Repo, branch: string): string | null {
  return repo.refs.get(branchRef(branch)) ?? null;
}

/** Flatten a tree (recursively) into path -> {oid, mode}; empty map for a missing tree. */
function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, TreeEntry & { path: string }>): void {
  const obj = repo.objects.get(treeOid);
  if (obj === undefined || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, { ...entry, path });
  }
}

function flatOfCommit(repo: Repo, commitOid: string | null): Map<string, TreeEntry & { path: string }> {
  const out = new Map<string, TreeEntry & { path: string }>();
  if (commitOid === null) return out;
  const obj = repo.objects.get(commitOid);
  if (obj === undefined || obj.type !== 'commit') return out;
  flattenTree(repo, parseCommit(obj.data).tree, '', out);
  return out;
}

/** Rebuild nested tree objects from a flat path -> blob map; returns the root tree oid. */
function buildTreeFromFlat(repo: Repo, flat: Map<string, { oid: string; mode: string }>): string {
  interface Node {
    files: Map<string, { oid: string; mode: string }>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i] as string;
      if (!node.dirs.has(segment)) node.dirs.set(segment, { files: new Map(), dirs: new Map() });
      node = node.dirs.get(segment) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return build(root);
}

/** Create a commit on a branch from a flat file map; returns the commit oid. */
function commitFlat(repo: Repo, branch: string, flat: Map<string, { oid: string; mode: string }>, message: string): string {
  const tree = buildTreeFromFlat(repo, flat);
  const parent = tipOf(repo, branch);
  const data = buildCommitData({ tree, parents: parent === null ? [] : [parent], message, sec: nextSec() });
  const oid = storeObject(repo, 'commit', data);
  repo.refs.set(branchRef(branch), oid);
  repo.updatedSec = nextSec();
  return oid;
}

function commitTreeOf(repo: Repo, commitOid: string): string {
  const obj = repo.objects.get(commitOid);
  if (obj === undefined || obj.type !== 'commit') return '';
  return parseCommit(obj.data).tree;
}

/** Commits reachable from a tip, tip first, parents in stored order. */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    seen.add(oid);
    out.push(oid);
    const parents = parseCommit(obj.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i] as string);
  }
  return out;
}

// ---------------------------------------------------------------------------
// JSON serializers (GitHub shapes)

function nodeId(kind: string, id: number): string {
  return Buffer.from(`${kind}${id}`, 'utf8').toString('base64');
}

function userJson(base: string): Record<string, unknown> {
  return {
    login: OWNER,
    id: 1000,
    node_id: nodeId('User', 1000),
    avatar_url: '',
    gravatar_id: '',
    url: `${base}/api/v3/users/${OWNER}`,
    html_url: `${base}/${OWNER}`,
    type: 'User',
    site_admin: false,
  };
}

function repoJson(repo: Repo, base: string): Record<string, unknown> {
  const url = `${base}/api/v3/repos/${OWNER}/${repo.name}`;
  return {
    id: repo.id,
    node_id: nodeId('Repository', repo.id),
    name: repo.name,
    full_name: `${OWNER}/${repo.name}`,
    private: repo.isPrivate,
    owner: userJson(base),
    html_url: `${base}/${OWNER}/${repo.name}`,
    description: repo.description,
    fork: false,
    url,
    created_at: isoOf(repo.createdSec),
    updated_at: isoOf(repo.updatedSec),
    pushed_at: isoOf(repo.updatedSec),
    clone_url: `${base}/${OWNER}/${repo.name}.git`,
    git_url: `git://${base.replace(/^https?:\/\//, '')}/${OWNER}/${repo.name}.git`,
    ssh_url: `git@forge:${OWNER}/${repo.name}.git`,
    homepage: '',
    size: repo.objects.size,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    forks_count: 0,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
    license: null,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
    default_branch: repo.defaultBranch,
  };
}

function labelJson(repo: Repo, label: LabelRec, base: string): Record<string, unknown> {
  return {
    id: label.id,
    node_id: nodeId('Label', label.id),
    url: `${base}/api/v3/repos/${OWNER}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    description: label.description,
    default: false,
  };
}

function issueJson(repo: Repo, issue: IssueRec, base: string): Record<string, unknown> {
  const url = `${base}/api/v3/repos/${OWNER}/${repo.name}/issues/${issue.number}`;
  return {
    id: issue.id,
    node_id: nodeId('Issue', issue.id),
    url,
    repository_url: `${base}/api/v3/repos/${OWNER}/${repo.name}`,
    html_url: `${base}/${OWNER}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label === undefined ? { name } : labelJson(repo, label, base);
    }),
    user: userJson(base),
    assignees: [],
    milestone: null,
    comments: repo.comments.filter((comment) => comment.issueNumber === issue.number).length,
    created_at: isoOf(issue.createdSec),
    updated_at: isoOf(issue.updatedSec),
    closed_at: issue.closedSec === null ? null : isoOf(issue.closedSec),
  };
}

function commentJson(repo: Repo, comment: CommentRec, base: string): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: nodeId('IssueComment', comment.id),
    url: `${base}/api/v3/repos/${OWNER}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `${base}/${OWNER}/${repo.name}/issues/${comment.issueNumber}#issuecomment-${comment.id}`,
    issue_url: `${base}/api/v3/repos/${OWNER}/${repo.name}/issues/${comment.issueNumber}`,
    body: comment.body,
    user: userJson(base),
    created_at: isoOf(comment.createdSec),
    updated_at: isoOf(comment.createdSec),
  };
}

function pullJson(repo: Repo, pull: PullRec, base: string): Record<string, unknown> {
  const url = `${base}/api/v3/repos/${OWNER}/${repo.name}/pulls/${pull.number}`;
  const headSha = tipOf(repo, pull.headRef) ?? pull.headSha;
  const baseSha = tipOf(repo, pull.baseRef) ?? pull.baseSha;
  const side = (ref: string, sha: string): Record<string, unknown> => ({
    label: `${OWNER}:${ref}`,
    ref,
    sha,
    user: userJson(base),
    repo: repoJson(repo, base),
  });
  return {
    id: pull.id,
    node_id: nodeId('PullRequest', pull.id),
    url,
    html_url: `${base}/${OWNER}/${repo.name}/pull/${pull.number}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    body: pull.body,
    user: userJson(base),
    draft: false,
    head: side(pull.headRef, headSha),
    base: side(pull.baseRef, baseSha),
    merged: pull.merged,
    merged_at: pull.mergedSec === null ? null : isoOf(pull.mergedSec),
    merge_commit_sha: pull.mergeCommitSha,
    merged_by: pull.merged ? userJson(base) : null,
    comments: 0,
    commits: 0,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    created_at: isoOf(pull.createdSec),
    updated_at: isoOf(pull.updatedSec),
    closed_at: pull.state === 'closed' ? isoOf(pull.updatedSec) : null,
  };
}

function commitJson(repo: Repo, oid: string, base: string): Record<string, unknown> {
  const obj = repo.objects.get(oid) as GitObj;
  const commit = parseCommit(obj.data);
  const person = (line: string): Record<string, unknown> => {
    const match = /^(.*) <(.*)> (\d+) [+-]\d{4}$/.exec(line);
    if (match === null) return { name: line, email: '', date: isoOf(BASE_SEC) };
    return { name: match[1], email: match[2], date: isoOf(Number(match[3])) };
  };
  return {
    sha: oid,
    node_id: nodeId('Commit', repo.id * 100000 + oid.charCodeAt(0)),
    url: `${base}/api/v3/repos/${OWNER}/${repo.name}/commits/${oid}`,
    html_url: `${base}/${OWNER}/${repo.name}/commit/${oid}`,
    commit: {
      author: person(commit.author),
      committer: person(commit.committer),
      message: commit.message.replace(/\n$/, ''),
      tree: { sha: commit.tree, url: `${base}/api/v3/repos/${OWNER}/${repo.name}/git/trees/${commit.tree}` },
      comment_count: 0,
    },
    author: userJson(base),
    committer: userJson(base),
    parents: commit.parents.map((parent) => ({ sha: parent, url: `${base}/api/v3/repos/${OWNER}/${repo.name}/commits/${parent}` })),
  };
}

// ---------------------------------------------------------------------------
// HTTP plumbing

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  base: string;
  url: URL;
  body: Buffer;
}

function sendJson(ctx: Ctx, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  ctx.res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  ctx.res.end(text);
}

function sendError(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

function sendNoContent(ctx: Ctx): void {
  ctx.res.writeHead(204, { 'x-github-request-id': nextRequestId() });
  ctx.res.end();
}

/** Parse a JSON request body; `{}` for an empty body, null for malformed JSON. */
function jsonBody(ctx: Ctx): Record<string, unknown> | null {
  if (ctx.body.length === 0) return {};
  try {
    const value = JSON.parse(ctx.body.toString('utf8')) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

function str(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}
function boolOr(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function authed(ctx: Ctx): boolean {
  const header = ctx.req.headers.authorization ?? '';
  if (TOKEN === '') return header.startsWith('Bearer ');
  const expected = Buffer.from(`Bearer ${TOKEN}`, 'utf8');
  const actual = Buffer.from(header, 'utf8');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

interface Page {
  items: unknown[];
  link: string | null;
}

function paginate(ctx: Ctx, all: unknown[], path: string): Page {
  const perPageRaw = Number(ctx.url.searchParams.get('per_page') ?? '30');
  const pageRaw = Number(ctx.url.searchParams.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  const start = (page - 1) * perPage;
  const items = all.slice(start, start + perPage);
  const lastPage = Math.max(1, Math.ceil(all.length / perPage));
  const parts: string[] = [];
  const linkUrl = (p: number): string => `${ctx.base}${path}?per_page=${perPage}&page=${p}`;
  if (page < lastPage) {
    parts.push(`<${linkUrl(page + 1)}>; rel="next"`);
    parts.push(`<${linkUrl(lastPage)}>; rel="last"`);
  }
  if (page > 1) {
    parts.push(`<${linkUrl(page - 1)}>; rel="prev"`);
    parts.push(`<${linkUrl(1)}>; rel="first"`);
  }
  return { items, link: parts.length > 0 ? parts.join(', ') : null };
}

function pageHeaders(page: Page): Record<string, string> {
  return page.link === null ? {} : { link: page.link };
}

// ---------------------------------------------------------------------------
// REST v3 handlers

function findRepo(ctx: Ctx, owner: string, name: string): Repo | null {
  if (owner !== OWNER) return null;
  return repos.get(name) ?? null;
}

function handleCreateRepo(ctx: Ctx): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const name = str(body.name);
  if (name === '') return sendError(ctx, 422, 'Repository creation failed.');
  if (repos.has(name)) {
    return sendJson(ctx, 422, {
      message: 'Repository creation failed.',
      errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }],
    });
  }
  const repo = createRepoRec(name, str(body.description), boolOr(body.private, false), str(body.default_branch, 'main') || 'main');
  return sendJson(ctx, 201, repoJson(repo, ctx.base));
}

function handleListUserRepos(ctx: Ctx): void {
  const all = [...repos.values()].map((repo) => repoJson(repo, ctx.base));
  const page = paginate(ctx, all, '/api/v3/user/repos');
  sendJson(ctx, 200, page.items, pageHeaders(page));
}

function resolveRefTip(repo: Repo, ref: string): string | null {
  if (/^[0-9a-f]{40}$/.test(ref) && repo.objects.has(ref)) return ref;
  return repo.refs.get(branchRef(ref)) ?? repo.refs.get(ref) ?? null;
}

/** The tree oid a ref (or the default branch) points at, or null when unborn. */
function refTree(repo: Repo, ref: string | null): { tip: string; tree: string } | null {
  const tip = ref === null ? tipOf(repo, repo.defaultBranch) : resolveRefTip(repo, ref);
  if (tip === null) return null;
  const tree = commitTreeOf(repo, tip);
  return tree === '' ? null : { tip, tree };
}

/** Walk to the tree object for a directory path ('' is the root); null when absent. */
function dirTreeOid(repo: Repo, rootTree: string, dirPath: string): string | null {
  if (dirPath === '') return rootTree;
  let current = rootTree;
  for (const segment of dirPath.split('/')) {
    const obj = repo.objects.get(current);
    if (obj === undefined || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
    if (entry === undefined) return null;
    current = entry.oid;
  }
  return current;
}

/** The blob entry for a file path under a root tree; null when absent. */
function fileEntry(repo: Repo, rootTree: string, filePath: string): TreeEntry | null {
  const segments = filePath.split('/');
  let current = rootTree;
  for (let i = 0; i < segments.length; i += 1) {
    const obj = repo.objects.get(current);
    if (obj === undefined || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((candidate) => candidate.name === segments[i]);
    if (entry === undefined) return null;
    if (i === segments.length - 1) return entry.mode === '40000' ? null : entry;
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

function contentFileJson(repo: Repo, filePath: string, entry: TreeEntry, base: string): Record<string, unknown> {
  const obj = repo.objects.get(entry.oid) as GitObj;
  const name = filePath.slice(filePath.lastIndexOf('/') + 1);
  return {
    type: 'file',
    encoding: 'base64',
    size: obj.data.length,
    name,
    path: filePath,
    content: obj.data.toString('base64'),
    sha: entry.oid,
    url: `${base}/api/v3/repos/${OWNER}/${repo.name}/contents/${filePath}`,
    html_url: `${base}/${OWNER}/${repo.name}/blob/${repo.defaultBranch}/${filePath}`,
    git_url: `${base}/api/v3/repos/${OWNER}/${repo.name}/git/blobs/${entry.oid}`,
    download_url: `${base}/${OWNER}/${repo.name}/raw/${repo.defaultBranch}/${filePath}`,
  };
}

function handleGetContents(ctx: Ctx, repo: Repo, rawPath: string): void {
  const ref = ctx.url.searchParams.get('ref');
  const resolved = refTree(repo, ref);
  if (resolved === null) return sendError(ctx, 404, 'Not Found');
  const path = rawPath.replace(/^\/+|\/+$/g, '');
  if (path !== '') {
    const entry = fileEntry(repo, resolved.tree, path);
    if (entry !== null) return sendJson(ctx, 200, contentFileJson(repo, path, entry, ctx.base));
  }
  const dirOid = dirTreeOid(repo, resolved.tree, path);
  if (dirOid === null) return sendError(ctx, 404, 'Not Found');
  const obj = repo.objects.get(dirOid) as GitObj;
  const entries = parseTree(obj.data).map((entry) => {
    const childPath = path === '' ? entry.name : `${path}/${entry.name}`;
    const child = repo.objects.get(entry.oid);
    return {
      type: entry.mode === '40000' ? 'dir' : 'file',
      size: entry.mode === '40000' || child === undefined ? 0 : child.data.length,
      name: entry.name,
      path: childPath,
      sha: entry.oid,
      url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/contents/${childPath}`,
      html_url: `${ctx.base}/${OWNER}/${repo.name}/blob/${repo.defaultBranch}/${childPath}`,
      git_url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/git/${entry.mode === '40000' ? 'trees' : 'blobs'}/${entry.oid}`,
      download_url: entry.mode === '40000' ? null : `${ctx.base}/${OWNER}/${repo.name}/raw/${repo.defaultBranch}/${childPath}`,
    };
  });
  return sendJson(ctx, 200, entries);
}

function handlePutContents(ctx: Ctx, repo: Repo, rawPath: string): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const filePath = rawPath.replace(/^\/+|\/+$/g, '');
  if (filePath === '') return sendError(ctx, 422, 'Invalid request.');
  const branch = str(body.branch, repo.defaultBranch) || repo.defaultBranch;
  const message = str(body.message, 'Update file');
  const encoded = str(body.content);
  const data = Buffer.from(encoded.replace(/[\r\n\t ]+/g, ''), 'base64');
  const flat = flatOfCommit(repo, tipOf(repo, branch));
  const existing = flat.get(filePath);
  const givenSha = typeof body.sha === 'string' ? body.sha : undefined;
  if (existing !== undefined) {
    if (givenSha === undefined) return sendError(ctx, 422, 'Invalid request.\n\n"sha" wasn\'t supplied.');
    if (givenSha !== existing.oid) return sendError(ctx, 409, `${filePath} does not match ${givenSha}`);
  } else if (givenSha !== undefined) {
    return sendError(ctx, 404, 'Not Found');
  }
  const blobOid = storeObject(repo, 'blob', data);
  flat.set(filePath, { oid: blobOid, mode: '100644' });
  const flatSimple = new Map<string, { oid: string; mode: string }>();
  for (const [path, entry] of flat) flatSimple.set(path, { oid: entry.oid, mode: entry.mode });
  const commitSha = commitFlat(repo, branch, flatSimple, message);
  const created = existing === undefined;
  return sendJson(ctx, created ? 201 : 200, {
    content: {
      type: 'file',
      encoding: 'base64',
      size: data.length,
      name: filePath.slice(filePath.lastIndexOf('/') + 1),
      path: filePath,
      content: data.toString('base64'),
      sha: blobOid,
      url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/contents/${filePath}`,
    },
    commit: {
      sha: commitSha,
      url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/commits/${commitSha}`,
      message,
      tree: { sha: commitTreeOf(repo, commitSha) },
      parents: commitSha === '' ? [] : parseCommit((repo.objects.get(commitSha) as GitObj).data).parents.map((sha) => ({ sha })),
    },
  });
}

function handleDeleteContents(ctx: Ctx, repo: Repo, rawPath: string): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const filePath = rawPath.replace(/^\/+|\/+$/g, '');
  const branch = str(body.branch, repo.defaultBranch) || repo.defaultBranch;
  const message = str(body.message, 'Delete file');
  const flat = flatOfCommit(repo, tipOf(repo, branch));
  if (!flat.has(filePath)) return sendError(ctx, 404, 'Not Found');
  flat.delete(filePath);
  const flatSimple = new Map<string, { oid: string; mode: string }>();
  for (const [path, entry] of flat) flatSimple.set(path, { oid: entry.oid, mode: entry.mode });
  const commitSha = commitFlat(repo, branch, flatSimple, message);
  return sendJson(ctx, 200, { content: null, commit: { sha: commitSha, url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/commits/${commitSha}`, message } });
}

function handleCreateLabel(ctx: Ctx, repo: Repo): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const name = str(body.name);
  if (name === '') return sendError(ctx, 422, 'Validation Failed');
  const existing = repo.labels.get(name);
  if (existing !== undefined) return sendJson(ctx, 422, { message: 'Validation Failed', errors: [{ resource: 'Label', code: 'already_exists', field: 'name' }] });
  const label: LabelRec = { id: nextLabelId, name, color: str(body.color, 'ededed'), description: typeof body.description === 'string' ? body.description : null };
  nextLabelId += 1;
  repo.labels.set(name, label);
  return sendJson(ctx, 201, labelJson(repo, label, ctx.base));
}

function labelNamesOf(body: Record<string, unknown>): string[] {
  const raw = body.labels;
  if (!Array.isArray(raw)) return [];
  const names: string[] = [];
  for (const item of raw) {
    if (typeof item === 'string') names.push(item);
    else if (typeof item === 'object' && item !== null && typeof (item as Record<string, unknown>).name === 'string') names.push((item as Record<string, unknown>).name as string);
  }
  return names;
}

function handleCreateIssue(ctx: Ctx, repo: Repo): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const labels = labelNamesOf(body);
  for (const name of labels) {
    if (!repo.labels.has(name)) return sendError(ctx, 422, 'Validation Failed: label not found');
  }
  const sec = nextSec();
  const issue: IssueRec = {
    id: nextIssueId,
    number: repo.nextNumber,
    title: str(body.title),
    body: str(body.body),
    state: 'open',
    labels,
    createdSec: sec,
    updatedSec: sec,
    closedSec: null,
  };
  nextIssueId += 1;
  repo.nextNumber += 1;
  repo.issues.set(issue.number, issue);
  return sendJson(ctx, 201, issueJson(repo, issue, ctx.base));
}

function handleListIssues(ctx: Ctx, repo: Repo): void {
  const state = ctx.url.searchParams.get('state') ?? 'open';
  let list = [...repo.issues.values()];
  if (state !== 'all') list = list.filter((issue) => issue.state === state);
  const direction = ctx.url.searchParams.get('direction') ?? 'desc';
  list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
  const page = paginate(ctx, list.map((issue) => issueJson(repo, issue, ctx.base)), `/api/v3/repos/${OWNER}/${repo.name}/issues`);
  sendJson(ctx, 200, page.items, pageHeaders(page));
}

function handlePatchIssue(ctx: Ctx, repo: Repo, issue: IssueRec): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  if (typeof body.title === 'string') issue.title = body.title;
  if (typeof body.body === 'string') issue.body = body.body;
  if (body.labels !== undefined) {
    const labels = labelNamesOf(body);
    for (const name of labels) if (!repo.labels.has(name)) return sendError(ctx, 422, 'Validation Failed: label not found');
    issue.labels = labels;
  }
  if (body.state === 'closed' || body.state === 'open') {
    issue.state = body.state;
    issue.closedSec = body.state === 'closed' ? nextSec() : null;
  }
  issue.updatedSec = nextSec();
  return sendJson(ctx, 200, issueJson(repo, issue, ctx.base));
}

function handleCreateComment(ctx: Ctx, repo: Repo, issue: IssueRec): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const comment: CommentRec = { id: nextCommentId, issueNumber: issue.number, body: str(body.body), createdSec: nextSec() };
  nextCommentId += 1;
  repo.comments.push(comment);
  return sendJson(ctx, 201, commentJson(repo, comment, ctx.base));
}

/** Line-based diff counts between two texts (LCS), for the pull-files view. */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  const dp: number[] = new Array((oldLines.length + 1) * (newLines.length + 1)).fill(0) as number[];
  const width = newLines.length + 1;
  for (let i = oldLines.length - 1; i >= 0; i -= 1) {
    for (let j = newLines.length - 1; j >= 0; j -= 1) {
      dp[i * width + j] = oldLines[i] === newLines[j] ? (dp[(i + 1) * width + j + 1] as number) + 1 : Math.max(dp[(i + 1) * width + j] as number, dp[i * width + j + 1] as number);
    }
  }
  const lcs = dp[0] as number;
  return { additions: newLines.length - lcs, deletions: oldLines.length - lcs };
}

function pullFiles(repo: Repo, pull: PullRec): Record<string, unknown>[] {
  const baseTip = tipOf(repo, pull.baseRef) ?? pull.baseSha;
  const headTip = tipOf(repo, pull.headRef) ?? pull.headSha;
  const base = mergeBase(repo.objects, baseTip, headTip) ?? baseTip;
  const from = flatOfCommit(repo, base);
  const to = flatOfCommit(repo, headTip);
  const paths = new Set<string>([...from.keys(), ...to.keys()]);
  const files: Record<string, unknown>[] = [];
  for (const path of [...paths].sort()) {
    const before = from.get(path);
    const after = to.get(path);
    if (before !== undefined && after !== undefined && before.oid === after.oid) continue;
    const oldText = before === undefined ? '' : ((repo.objects.get(before.oid) as GitObj | undefined)?.data.toString('utf8') ?? '');
    const newText = after === undefined ? '' : ((repo.objects.get(after.oid) as GitObj | undefined)?.data.toString('utf8') ?? '');
    const { additions, deletions } = lineDiff(oldText, newText);
    files.push({
      sha: after?.oid ?? before?.oid ?? '',
      filename: path,
      status: before === undefined ? 'added' : after === undefined ? 'removed' : 'modified',
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: `${''}/api/v3/repos/${OWNER}/${repo.name}/git/blobs/${after?.oid ?? ''}`,
    });
  }
  return files;
}

/** Three-way tree merge; returns the merged flat map, or null on a conflict. */
function mergeFlats(
  repo: Repo,
  baseFlat: Map<string, TreeEntry & { path: string }>,
  ourFlat: Map<string, TreeEntry & { path: string }>,
  theirFlat: Map<string, TreeEntry & { path: string }>,
): Map<string, { oid: string; mode: string }> | null {
  const paths = new Set<string>([...baseFlat.keys(), ...ourFlat.keys(), ...theirFlat.keys()]);
  const out = new Map<string, { oid: string; mode: string }>();
  const same = (a: (TreeEntry & { path: string }) | undefined, b: (TreeEntry & { path: string }) | undefined): boolean =>
    (a === undefined && b === undefined) || (a !== undefined && b !== undefined && a.oid === b.oid && a.mode === b.mode);
  for (const path of paths) {
    const base = baseFlat.get(path);
    const ours = ourFlat.get(path);
    const theirs = theirFlat.get(path);
    let winner: (TreeEntry & { path: string }) | undefined;
    if (same(ours, theirs)) winner = ours;
    else if (same(base, ours)) winner = theirs;
    else if (same(base, theirs)) winner = ours;
    else return null;
    if (winner !== undefined) out.set(path, { oid: winner.oid, mode: winner.mode });
  }
  return out;
}

function handleCreatePull(ctx: Ctx, repo: Repo): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  const stripOwner = (ref: string): string => (ref.includes(':') ? ref.slice(ref.indexOf(':') + 1) : ref);
  const headRef = stripOwner(str(body.head));
  const baseRef = stripOwner(str(body.base, repo.defaultBranch)) || repo.defaultBranch;
  const headSha = tipOf(repo, headRef);
  const baseSha = tipOf(repo, baseRef);
  if (headSha === null || baseSha === null) return sendError(ctx, 422, 'Validation Failed: head or base ref not found');
  const sec = nextSec();
  const pull: PullRec = {
    id: nextPullId,
    number: repo.nextNumber,
    title: str(body.title),
    body: str(body.body),
    state: 'open',
    headRef,
    baseRef,
    headSha,
    baseSha,
    merged: false,
    mergedSec: null,
    mergeCommitSha: null,
    createdSec: sec,
    updatedSec: sec,
  };
  nextPullId += 1;
  repo.nextNumber += 1;
  repo.pulls.set(pull.number, pull);
  return sendJson(ctx, 201, pullJson(repo, pull, ctx.base));
}

function handleMergePull(ctx: Ctx, repo: Repo, pull: PullRec): void {
  const body = jsonBody(ctx);
  if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
  if (pull.merged || pull.state !== 'open') return sendError(ctx, 405, 'Pull Request is not mergeable');
  const baseTip = tipOf(repo, pull.baseRef) ?? pull.baseSha;
  const headTip = tipOf(repo, pull.headRef) ?? pull.headSha;
  const base = mergeBase(repo.objects, baseTip, headTip);
  const baseFlat = flatOfCommit(repo, base);
  const ourFlat = flatOfCommit(repo, baseTip);
  const theirFlat = flatOfCommit(repo, headTip);
  const mergedFlat = mergeFlats(repo, baseFlat, ourFlat, theirFlat);
  if (mergedFlat === null) return sendError(ctx, 405, 'Pull Request is not mergeable');
  const tree = buildTreeFromFlat(repo, mergedFlat);
  const message = `${pull.title} (#${pull.number})`;
  const data = buildCommitData({ tree, parents: [baseTip], message, sec: nextSec() });
  const sha = storeObject(repo, 'commit', data);
  repo.refs.set(branchRef(pull.baseRef), sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedSec = nextSec();
  pull.mergeCommitSha = sha;
  pull.updatedSec = pull.mergedSec;
  return sendJson(ctx, 200, { sha, merged: true, message: 'Pull Request successfully merged' });
}

function handleListPulls(ctx: Ctx, repo: Repo): void {
  const state = ctx.url.searchParams.get('state') ?? 'open';
  let list = [...repo.pulls.values()];
  if (state === 'open') list = list.filter((pull) => pull.state === 'open');
  else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
  list.sort((a, b) => a.number - b.number);
  const page = paginate(ctx, list.map((pull) => pullJson(repo, pull, ctx.base)), `/api/v3/repos/${OWNER}/${repo.name}/pulls`);
  sendJson(ctx, 200, page.items, pageHeaders(page));
}

// ---------------------------------------------------------------------------
// git smart HTTP

function peeledOf(repo: Repo, oid: string): string | null {
  let current = oid;
  const seen = new Set<string>();
  for (;;) {
    if (seen.has(current)) return null;
    seen.add(current);
    const obj = repo.objects.get(current);
    if (obj === undefined) return null;
    if (obj.type !== 'tag') return current === oid ? null : current;
    const target = parseTagTarget(obj.data);
    if (target === '') return null;
    current = target;
  }
}

function sortedRefs(repo: Repo): { name: string; oid: string }[] {
  return [...repo.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function sendRaw(ctx: Ctx, status: number, contentType: string, body: Buffer): void {
  ctx.res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': nextRequestId() });
  ctx.res.end(body);
}

function handleInfoRefs(ctx: Ctx, repo: Repo, service: string): void {
  const wantsV2 = service === 'git-upload-pack' && (ctx.req.headers['git-protocol'] ?? '').includes('version=2');
  if (wantsV2) {
    const body = Buffer.concat([
      pktLine('version 2\n'),
      pktLine('agent=forge/1.0\n'),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow\n'),
      pktLine('object-format=sha1\n'),
      PKT_FLUSH,
    ]);
    return sendRaw(ctx, 200, 'application/x-git-upload-pack-advertisement', body);
  }
  const caps =
    service === 'git-upload-pack'
      ? `side-band-64k ofs-delta shallow thin-pack multi_ack_detailed symref=HEAD:refs/heads/${repo.defaultBranch} agent=forge/1.0`
      : 'report-status side-band-64k delete-refs';
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = sortedRefs(repo);
  const defaultTip = tipOf(repo, repo.defaultBranch);
  const lines: string[] = [];
  if (defaultTip !== null) lines.push(`${defaultTip} HEAD`);
  for (const ref of refs) {
    lines.push(`${ref.oid} ${ref.name}`);
    const peeled = peeledOf(repo, ref.oid);
    if (peeled !== null) lines.push(`${peeled} ${ref.name}^{}`);
  }
  if (lines.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    lines.forEach((line, index) => {
      parts.push(pktLine(index === 0 ? `${line}\0${caps}\n` : `${line}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  return sendRaw(ctx, 200, `application/x-${service}-advertisement`, Buffer.concat(parts));
}

/** Data lines after the delim packet of a v2 command request. */
function argsAfterDelim(packets: Packet[]): string[] {
  const lines: string[] = [];
  let after = false;
  for (const packet of packets) {
    if (packet === 'delim') {
      after = true;
      continue;
    }
    if (packet === 'flush') break;
    if (after && Buffer.isBuffer(packet)) lines.push(packet.toString('utf8').replace(/\n$/, ''));
  }
  return lines;
}

function handleLsRefs(ctx: Ctx, repo: Repo, packets: Packet[]): void {
  const args = argsAfterDelim(packets);
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((arg) => arg.startsWith('ref-prefix ')).map((arg) => arg.slice('ref-prefix '.length));
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const defaultTip = tipOf(repo, repo.defaultBranch);
  if (matches('HEAD')) {
    if (defaultTip !== null) {
      lines.push(`${defaultTip} HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}`);
    } else if (unborn) {
      lines.push(`unborn HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}`);
    }
  }
  for (const ref of sortedRefs(repo)) {
    if (!matches(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (peel) {
      const peeled = peeledOf(repo, ref.oid);
      if (peeled !== null) line += ` peeled:${peeled}`;
    }
    lines.push(line);
  }
  const body = Buffer.concat([...lines.map((line) => pktLine(`${line}\n`)), PKT_FLUSH]);
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', body);
}

interface FetchPlan {
  objects: GitObj[];
  shallow: string[];
  unshallow: string[];
}

function computeFetch(repo: Repo, wants: string[], haves: string[], clientShallow: Set<string>, depth: number | null): FetchPlan {
  // Phase A: which commits are included, at which generation from a want.
  const commitGens = new Map<string, number>();
  const extraRoots: string[] = [];
  const queue: { oid: string; gen: number }[] = wants.map((oid) => ({ oid, gen: 1 }));
  while (queue.length > 0) {
    const { oid, gen } = queue.shift() as { oid: string; gen: number };
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      extraRoots.push(oid);
      const target = parseTagTarget(obj.data);
      if (target !== '') queue.push({ oid: target, gen });
      continue;
    }
    if (obj.type !== 'commit') {
      extraRoots.push(oid);
      continue;
    }
    const known = commitGens.get(oid);
    if (known !== undefined && known <= gen) continue;
    commitGens.set(oid, gen);
    if (depth === null || gen < depth) {
      for (const parent of parseCommit(obj.data).parents) queue.push({ oid: parent, gen: gen + 1 });
    }
  }
  const include = new Set<string>();
  for (const oid of extraRoots) for (const found of collectReachable(repo.objects, [oid])) include.add(found);
  for (const oid of commitGens.keys()) {
    include.add(oid);
    const tree = commitTreeOf(repo, oid);
    if (tree !== '') for (const found of collectReachable(repo.objects, [tree])) include.add(found);
  }
  // Exclusions: what the client already holds. A shallow-held commit's parents are not held.
  const exclude = new Set<string>();
  for (const have of haves) {
    if (clientShallow.has(have)) {
      const obj = repo.objects.get(have);
      if (obj === undefined) continue;
      exclude.add(have);
      if (obj.type === 'commit') {
        const tree = commitTreeOf(repo, have);
        if (tree !== '') for (const found of collectReachable(repo.objects, [tree])) exclude.add(found);
      } else {
        for (const found of collectReachable(repo.objects, [have])) exclude.add(found);
      }
    } else {
      for (const found of collectReachable(repo.objects, [have])) exclude.add(found);
    }
  }
  const sendOids = [...include].filter((oid) => !exclude.has(oid)).sort();
  const objects = sendOids.map((oid) => repo.objects.get(oid) as GitObj);
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const oid of commitGens.keys()) {
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'commit') continue;
      const parents = parseCommit(obj.data).parents;
      const cut = parents.some((parent) => !commitGens.has(parent) && repo.objects.has(parent));
      if (cut) shallow.push(oid);
      else if (clientShallow.has(oid)) unshallow.push(oid);
    }
    for (const oid of clientShallow) {
      if (commitGens.has(oid) && !shallow.includes(oid) && !unshallow.includes(oid)) unshallow.push(oid);
    }
  }
  return { objects, shallow: shallow.sort(), unshallow: unshallow.sort() };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  const chunkSize = 16384;
  for (let offset = 0; offset < pack.length; offset += chunkSize) {
    const chunk = pack.subarray(offset, offset + chunkSize);
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  if (parts.length === 0) parts.push(pktLine(Buffer.concat([Buffer.from([1]), Buffer.alloc(0)])));
  return parts;
}

function handleFetchV2(ctx: Ctx, repo: Repo, packets: Packet[]): void {
  const args = argsAfterDelim(packets);
  const wants: string[] = [];
  const haves: string[] = [];
  const clientShallow = new Set<string>();
  let depth: number | null = null;
  for (const arg of args) {
    if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) clientShallow.add(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) depth = Number(arg.slice(7).trim());
  }
  if (depth !== null && (!Number.isFinite(depth) || depth <= 0)) depth = null;
  const plan = computeFetch(repo, wants, haves, clientShallow, depth);
  const pack = writePack(plan.objects);
  const parts: Buffer[] = [pktLine('acknowledgments\n')];
  const common = haves.filter((have) => repo.objects.has(have));
  if (common.length === 0) parts.push(pktLine('NAK\n'));
  else for (const have of common) parts.push(pktLine(`ACK ${have}\n`));
  parts.push(PKT_DELIM);
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(...sidebandPackets(pack));
  parts.push(PKT_FLUSH);
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleFetchV0(ctx: Ctx, repo: Repo, packets: Packet[]): void {
  const wants: string[] = [];
  const haves: string[] = [];
  const clientShallow = new Set<string>();
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet === 'flush') {
      section += 1;
      continue;
    }
    if (!Buffer.isBuffer(packet)) continue;
    const line = packet.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (line.startsWith('want ')) wants.push((line.split(' ')[1] as string) ?? '');
      else if (line.startsWith('shallow ')) clientShallow.add(line.slice(8).trim());
      else if (line.startsWith('deepen ')) depth = Number(line.slice(7).trim());
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5).trim());
    }
  }
  if (depth !== null && (!Number.isFinite(depth) || depth <= 0)) depth = null;
  const plan = computeFetch(repo, wants, haves, clientShallow, depth);
  const pack = writePack(plan.objects);
  const parts: Buffer[] = [];
  for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(pktLine('NAK\n'));
  parts.push(...sidebandPackets(pack));
  parts.push(PKT_FLUSH);
  sendRaw(ctx, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

function handleUploadPack(ctx: Ctx, repo: Repo): void {
  const { packets } = decodePackets(ctx.body);
  const lines = packetLines(packets);
  const first = lines[0] ?? '';
  try {
    if (first.startsWith('command=ls-refs')) return handleLsRefs(ctx, repo, packets);
    if (first.startsWith('command=fetch')) return handleFetchV2(ctx, repo, packets);
    return handleFetchV0(ctx, repo, packets);
  } catch {
    return sendRaw(ctx, 400, 'text/plain; charset=utf-8', Buffer.from('error: bad request\n', 'utf8'));
  }
}

interface PushCommandRec {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(ctx: Ctx, repo: Repo): void {
  const { packets, rest } = decodePackets(ctx.body);
  const commands: PushCommandRec[] = [];
  let capabilities = '';
  for (const packet of packets) {
    if (packet === 'flush') break;
    if (!Buffer.isBuffer(packet)) continue;
    let line = packet.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) {
      capabilities = line.slice(nul + 1);
      line = line.slice(0, nul);
    }
    const parts = line.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
  }
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (rest.length > 0) {
    try {
      const objects = readPack(rest, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message.replace(/[\r\n]+/g, ' ') : 'error';
    }
  }
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  for (const command of commands) {
    if (!unpackOk) {
      results.push({ ref: command.ref, ok: false, reason: 'unpacker error' });
      continue;
    }
    if (command.newOid === ZERO_OID) {
      repo.refs.delete(command.ref);
      results.push({ ref: command.ref, ok: true, reason: '' });
      continue;
    }
    if (!repo.objects.has(command.newOid)) {
      results.push({ ref: command.ref, ok: false, reason: 'missing object' });
      continue;
    }
    const current = repo.refs.get(command.ref) ?? null;
    const base = current ?? (command.oldOid !== ZERO_OID ? command.oldOid : null);
    if (base !== null && base !== command.newOid && !isAncestor(repo.objects, base, command.newOid)) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(command.ref, command.newOid);
    results.push({ ref: command.ref, ok: true, reason: '' });
  }
  if (!capabilities.includes('report-status')) {
    return sendRaw(ctx, 200, 'application/x-git-receive-pack-result', Buffer.alloc(0));
  }
  const reportLines = [`unpack ${unpackDetail}`];
  for (const result of results) reportLines.push(result.ok ? `ok ${result.ref}` : `ng ${result.ref} ${result.reason}`);
  const inner = Buffer.concat([...reportLines.map((line) => pktLine(`${line}\n`)), PKT_FLUSH]);
  let body: Buffer;
  if (capabilities.includes('side-band-64k')) {
    const parts: Buffer[] = [];
    const chunkSize = 32768;
    for (let offset = 0; offset < inner.length; offset += chunkSize) {
      parts.push(pktLine(Buffer.concat([Buffer.from([1]), inner.subarray(offset, offset + chunkSize)])));
    }
    parts.push(PKT_FLUSH);
    body = Buffer.concat(parts);
  } else {
    body = inner;
  }
  return sendRaw(ctx, 200, 'application/x-git-receive-pack-result', body);
}

// ---------------------------------------------------------------------------
// routing

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function routeRest(ctx: Ctx, segments: string[]): void {
  const method = ctx.req.method ?? 'GET';
  // /api/v3 root and meta
  if (segments.length === 2 && method === 'GET') {
    return sendJson(
      ctx,
      200,
      {
        current_user_url: `${ctx.base}/api/v3/user`,
        repository_url: `${ctx.base}/api/v3/repos/{owner}/{repo}`,
        rate_limit_url: `${ctx.base}/api/v3/rate_limit`,
        issue_url: `${ctx.base}/api/v3/repos/{owner}/{repo}/issues/{number}`,
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
  }
  if (segments[2] === 'meta' && segments.length === 3 && method === 'GET') {
    return sendJson(ctx, 200, { verifiable_password_authentication: false, github_services_sha: 'forge', installed_version: '1.0.0' });
  }
  if (segments[2] === 'rate_limit' && segments.length === 3 && method === 'GET') {
    return sendJson(ctx, 200, { resources: { core: { limit: 5000, remaining: 5000, reset: BASE_SEC + 3600 } }, rate: { limit: 5000, remaining: 5000, reset: BASE_SEC + 3600 } });
  }
  if (segments[2] === 'user' && segments.length === 3 && method === 'GET') {
    return sendJson(ctx, 200, { ...userJson(ctx.base), name: OWNER, type: 'User' });
  }
  if (segments[2] === 'user' && segments[3] === 'repos' && segments.length === 4) {
    if (method === 'POST') return handleCreateRepo(ctx);
    if (method === 'GET') return handleListUserRepos(ctx);
    return sendError(ctx, 404, 'Not Found');
  }
  if (segments[2] !== 'repos' || segments.length < 5) return sendError(ctx, 404, 'Not Found');
  const repo = findRepo(ctx, segments[3] as string, segments[4] as string);
  if (repo === null) return sendError(ctx, 404, 'Not Found');
  const rest = segments.slice(5);

  if (rest.length === 0) {
    if (method === 'GET') return sendJson(ctx, 200, repoJson(repo, ctx.base));
    if (method === 'PATCH') {
      const body = jsonBody(ctx);
      if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      if (typeof body.name === 'string' && body.name !== '' && body.name !== repo.name && !repos.has(body.name)) {
        repos.delete(repo.name);
        repo.name = body.name;
        repos.set(repo.name, repo);
      }
      repo.updatedSec = nextSec();
      return sendJson(ctx, 200, repoJson(repo, ctx.base));
    }
    if (method === 'DELETE') {
      repos.delete(repo.name);
      return sendNoContent(ctx);
    }
    return sendError(ctx, 404, 'Not Found');
  }

  if (rest[0] === 'branches' && method === 'GET') {
    if (rest.length === 1) {
      const branches = [...repo.refs.entries()]
        .filter(([name]) => name.startsWith('refs/heads/'))
        .map(([name, oid]) => ({ name: name.slice('refs/heads/'.length), commit: { sha: oid, url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/commits/${oid}` }, protected: false }))
        .sort((a, b) => (a.name < b.name ? -1 : 1));
      return sendJson(ctx, 200, branches);
    }
    const branch = rest.slice(1).join('/');
    const tip = tipOf(repo, branch);
    if (tip === null) return sendError(ctx, 404, 'Not Found');
    return sendJson(ctx, 200, { name: branch, commit: commitJson(repo, tip, ctx.base), protected: false });
  }

  if (rest[0] === 'commits' && method === 'GET') {
    if (rest.length === 2) {
      const oid = rest[1] as string;
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'commit') return sendError(ctx, 404, 'Not Found');
      return sendJson(ctx, 200, commitJson(repo, oid, ctx.base));
    }
    const shaParam = ctx.url.searchParams.get('sha');
    const tip = shaParam === null ? tipOf(repo, repo.defaultBranch) : resolveRefTip(repo, shaParam);
    if (tip === null) return sendJson(ctx, 200, []);
    return sendJson(ctx, 200, listCommits(repo, tip).map((oid) => commitJson(repo, oid, ctx.base)));
  }

  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const body = jsonBody(ctx);
      if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
      const ref = str(body.ref);
      const sha = str(body.sha);
      const obj = repo.objects.get(sha);
      if (!ref.startsWith('refs/') || obj === undefined) return sendError(ctx, 422, 'Validation Failed');
      if (repo.refs.has(ref)) return sendError(ctx, 422, 'Reference already exists');
      repo.refs.set(ref, sha);
      return sendJson(ctx, 201, {
        ref,
        node_id: nodeId('Ref', repo.id),
        url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/git/refs/${ref.slice('refs/'.length)}`,
        object: { type: obj.type, sha, url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/git/${obj.type}s/${sha}` },
      });
    }
    if (method === 'GET') {
      const refs = sortedRefs(repo).map((ref) => ({
        ref: ref.name,
        node_id: nodeId('Ref', repo.id),
        url: `${ctx.base}/api/v3/repos/${OWNER}/${repo.name}/git/refs/${ref.name.slice('refs/'.length)}`,
        object: { type: (repo.objects.get(ref.oid) as GitObj | undefined)?.type ?? 'commit', sha: ref.oid },
      }));
      return sendJson(ctx, 200, refs);
    }
    return sendError(ctx, 404, 'Not Found');
  }

  if (rest[0] === 'contents') {
    const rawPath = rest.slice(1).join('/');
    if (method === 'GET') return handleGetContents(ctx, repo, rawPath);
    if (method === 'PUT') return handlePutContents(ctx, repo, rawPath);
    if (method === 'DELETE') return handleDeleteContents(ctx, repo, rawPath);
    return sendError(ctx, 404, 'Not Found');
  }

  if (rest[0] === 'labels') {
    if (method === 'POST' && rest.length === 1) return handleCreateLabel(ctx, repo);
    if (method === 'GET' && rest.length === 1) return sendJson(ctx, 200, [...repo.labels.values()].map((label) => labelJson(repo, label, ctx.base)));
    return sendError(ctx, 404, 'Not Found');
  }

  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (method === 'POST') return handleCreateIssue(ctx, repo);
      if (method === 'GET') return handleListIssues(ctx, repo);
      return sendError(ctx, 404, 'Not Found');
    }
    const number = Number(rest[1]);
    const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;
    if (rest.length === 2) {
      if (issue === undefined) return sendError(ctx, 404, 'Not Found');
      if (method === 'GET') return sendJson(ctx, 200, issueJson(repo, issue, ctx.base));
      if (method === 'PATCH') return handlePatchIssue(ctx, repo, issue);
      return sendError(ctx, 404, 'Not Found');
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (issue === undefined) return sendError(ctx, 404, 'Not Found');
      if (method === 'POST') return handleCreateComment(ctx, repo, issue);
      if (method === 'GET') {
        return sendJson(ctx, 200, repo.comments.filter((comment) => comment.issueNumber === issue.number).map((comment) => commentJson(repo, comment, ctx.base)));
      }
      return sendError(ctx, 404, 'Not Found');
    }
    return sendError(ctx, 404, 'Not Found');
  }

  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (method === 'POST') return handleCreatePull(ctx, repo);
      if (method === 'GET') return handleListPulls(ctx, repo);
      return sendError(ctx, 404, 'Not Found');
    }
    const number = Number(rest[1]);
    const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;
    if (rest.length === 2 && method === 'GET') {
      if (pull === undefined) return sendError(ctx, 404, 'Not Found');
      return sendJson(ctx, 200, pullJson(repo, pull, ctx.base));
    }
    if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
      if (pull === undefined) return sendError(ctx, 404, 'Not Found');
      const files = pullFiles(repo, pull).map((file) => ({ ...file, blob_url: `${ctx.base}${file.blob_url}` }));
      return sendJson(ctx, 200, files);
    }
    if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
      if (pull === undefined) return sendError(ctx, 404, 'Not Found');
      return handleMergePull(ctx, repo, pull);
    }
    return sendError(ctx, 404, 'Not Found');
  }

  return sendError(ctx, 404, 'Not Found');
}

function route(ctx: Ctx): void {
  const method = ctx.req.method ?? 'GET';
  const path = ctx.url.pathname;
  if (method === 'GET' && path === '/healthz') {
    return sendJson(ctx, 200, { ok: true });
  }
  if (!authed(ctx)) return sendError(ctx, 401, 'Bad credentials');
  const segments = path.split('/').filter((segment) => segment !== '').map(decodeSegment);
  if (segments[0] === 'api' && segments[1] === 'v3') return routeRest(ctx, segments);
  if (path === '/api/graphql' && method === 'POST') {
    const body = jsonBody(ctx);
    if (body === null) return sendError(ctx, 400, 'Problems parsing JSON');
    return sendJson(ctx, 200, { data: {} });
  }
  if (path === '/mcp' && method === 'POST') {
    const body = jsonBody(ctx);
    if (body === null) {
      return sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }
    const id = (body as Record<string, unknown>).id ?? null;
    return sendJson(ctx, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } });
  }
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (gitMatch !== null) {
    const owner = decodeSegment(gitMatch[1] as string);
    const name = decodeSegment(gitMatch[2] as string);
    const repo = owner === OWNER ? repos.get(name) ?? null : null;
    if (repo === null) return sendError(ctx, 404, 'Not Found');
    const service = gitMatch[3] as string;
    if (service === 'info/refs' && method === 'GET') {
      const serviceName = ctx.url.searchParams.get('service') ?? '';
      if (serviceName !== 'git-upload-pack' && serviceName !== 'git-receive-pack') return sendError(ctx, 403, 'Forbidden');
      return handleInfoRefs(ctx, repo, serviceName);
    }
    if (service === 'git-upload-pack' && method === 'POST') return handleUploadPack(ctx, repo);
    if (service === 'git-receive-pack' && method === 'POST') return handleReceivePack(ctx, repo);
    return sendError(ctx, 404, 'Not Found');
  }
  return sendError(ctx, 404, 'Not Found');
}

function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      let url: URL;
      try {
        url = new URL(req.url ?? '/', 'http://entry');
      } catch {
        url = new URL('/', 'http://entry');
      }
      const host = req.headers.host ?? '127.0.0.1';
      const ctx: Ctx = { req, res, base: `http://${host}`, url, body: Buffer.concat(chunks) };
      try {
        route(ctx);
      } catch {
        if (!res.headersSent) sendError(ctx, 500, 'Internal Server Error');
        else res.end();
      }
    });
    req.on('error', () => {
      if (!res.headersSent) res.writeHead(400, { 'content-type': JSON_TYPE });
      res.end();
    });
  });
}

// ---------------------------------------------------------------------------
// lifecycle: bind ephemeral, register, poll /done, exit 0

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register answered HTTP ${res.status}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet; keep polling.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  if (ENV_URL === '') {
    process.stderr.write('[entry] MAKEFUN_ENV_URL is not set\n');
    process.exit(1);
  }
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${address.port}\n`);
  await register(address.port);
  process.stdout.write('[entry] registered; waiting for done\n');
  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
