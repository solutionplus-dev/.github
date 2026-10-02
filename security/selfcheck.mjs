#!/usr/bin/env node
// SolutionPlus security self-check (PolinRider / EtherHiding / Shai-Hulud).
//
// Read-only by default. Run it from anywhere inside a repo:
//   node security/selfcheck.mjs                 repo + git history + this machine
//   node security/selfcheck.mjs --fix           also neutralise what it finds (never touches git history or remotes)
//   node security/selfcheck.mjs --scan-dir ~/code   check every git repo under a folder
//   node security/selfcheck.mjs --install-hook  add a pre-push hook that blocks infected commits
//   node security/selfcheck.mjs --ci            CI mode: repo + history, no machine checks
// Other flags: --no-history, --no-machine, --repo <path>, --json, --quiet
//
// Exit codes: 0 clean, 1 findings at HIGH severity, 2 the check itself failed.
// It never prints secrets and never prints suspicious file content.
// Rules for agents: security/AGENT_SECURITY_RULES.md

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const VERSION = "2026-10-02.2";
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
};
const CI = flag("--ci");
const FIX = flag("--fix");
const JSON_OUT = flag("--json");
const QUIET = flag("--quiet");
const DO_HISTORY = !flag("--no-history");
const DO_MACHINE = !flag("--no-machine") && !CI;
const PLATFORM = process.platform;
const HOME = os.homedir();

// ---------------------------------------------------------------- indicators
// Markers are assembled from pieces so this file never matches itself.
const MARKERS = [
  new RegExp("global\\[\\s*['\"]" + "!" + "['\"]\\s*\\]"),
  new RegExp("global\\.i\\s*=\\s*['\"]" + "A8"),
];
const PAD = /[ \t]{120,}(?=\S)/g;
const OBF = new RegExp("_0" + "x[0-9a-f]{4,}", "g");
const FONT_MAGIC = {
  ".woff2": [Buffer.from("wOF2")],
  ".woff": [Buffer.from("wOFF")],
  ".ttf": [Buffer.from([0, 1, 0, 0]), Buffer.from("true"), Buffer.from("OTTO"), Buffer.from("typ1")],
  ".otf": [Buffer.from("OTTO"), Buffer.from([0, 1, 0, 0])],
};
const JS_EXT = new Set([".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"]);
const WORM_FILES = new Set(["temp_auto_push.bat", "temp_interactive_push.bat", "branch_structure.json"]);
const HULUD_FILES = new Set(["setup_bun.js", "bun_environment.js", "truffleSecrets.json", "actionsSecrets.json"]);
const ASSET_RUN = /\bnode\s+[^\s"'&|;]*\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico)\b/i;
const CONFIG_NAME = /(\.config\.[cm]?[jt]s$|babel|postcss|tailwind|eslint|metro|vite|next|webpack|rollup|jest|routes?\.[cm]?[jt]s$)/i;
// Git blob ids of payloads and loaders seen in SolutionPlus repos (2026-03 .. 2026-09).
const KNOWN_BAD = [
  "c7ffaad", "33b0e98", "4b1f700", "818b5de", "8e14837", "5e22662", "934d555", "6df5b2c", "974c14a",
  "45f9ea1", "1a828db", "8214532", "b0d43c4", "2d3918f", "cb4b0f8", "0b483a5", "376e125", "0c41fad",
  "d8ddf4c", "79ecf32", "8d0ace9", "5fd8e70", "788a483", "7369d64", "85a5e1e", "da3a37f", "975618d",
  "3155131", "4df7400", "b520ace", "e27448f", "61ce336", "0dfe6e3", "740081b",
];
const SKIP_DIRS = new Set(["node_modules", ".git", "Pods", "build", "dist", ".next", ".expo", "DerivedData", ".gradle", "vendor", ".turbo", ".cache", "coverage"]);
const MAX_SCAN_BYTES = 3 * 1024 * 1024;

const findings = [];
const actions = [];
const add = (severity, area, where, what, fix) => findings.push({ severity, area, where, what, fix: fix || "" });

const blobId = (buf) => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");
const isKnownBad = (sha) => KNOWN_BAD.some((p) => sha.startsWith(p));
const sh = (cmd, args, opts = {}) => {
  const { binary, ...rest } = opts;
  if (binary && typeof rest.input === "string") rest.input = Buffer.from(rest.input);
  const r = spawnSync(cmd, args, { encoding: binary ? "buffer" : "utf8", maxBuffer: 1 << 30, ...rest });
  return { ok: r.status === 0, out: r.stdout ?? (opts.binary ? Buffer.alloc(0) : ""), err: r.stderr ?? "" };
};
const git = (repo, args, opts) => sh("git", ["-C", repo, ...args], opts);

// Classify one file by path and content. Returns [{severity, what, kind}].
function classify(relPath, buf) {
  const out = [];
  const base = path.basename(relPath);
  const ext = path.extname(relPath).toLowerCase();
  const norm = relPath.split(path.sep).join("/");
  if (WORM_FILES.has(base)) out.push({ severity: "HIGH", kind: "wormfile", what: `PolinRider propagation file ${base}` });
  if (HULUD_FILES.has(base)) out.push({ severity: "HIGH", kind: "hulud", what: `Shai-Hulud artefact ${base}` });
  if (/(^|\/)\.github\/workflows\/shai-hulud[^/]*\.ya?ml$/i.test(norm)) out.push({ severity: "HIGH", kind: "hulud", what: "Shai-Hulud workflow" });
  if (FONT_MAGIC[ext] && buf.length > 0 && !FONT_MAGIC[ext].some((m) => buf.subarray(0, m.length).equals(m))) {
    out.push({ severity: "HIGH", kind: "fakefont", what: "font file whose bytes are not a font (likely a JavaScript payload)" });
  }
  if (FONT_MAGIC[ext] || buf.length > MAX_SCAN_BYTES) return out;
  const text = buf.toString("utf8");
  if (norm.endsWith(".vscode/tasks.json") || ext === ".code-workspace") {
    if (/"runOn"\s*:\s*"folderOpen"/.test(text)) {
      const asset = ASSET_RUN.test(text);
      out.push({ severity: asset || /"hide"\s*:\s*true/.test(text) ? "HIGH" : "MEDIUM", kind: "tasks", what: asset ? "editor task runs a font/image file with node on folder open (PolinRider loader)" : "editor task runs automatically on folder open" });
    }
  }
  if (norm.endsWith(".vscode/settings.json") || ext === ".code-workspace") {
    if (/"task\.allowAutomaticTasks"\s*:\s*(true|"on")/.test(text)) out.push({ severity: "HIGH", kind: "settings", what: "workspace enables automatic tasks (task.allowAutomaticTasks)" });
    if (/"terminal\.integrated\.hideOnStartup"\s*:\s*"always"/.test(text)) out.push({ severity: "MEDIUM", kind: "settings", what: "workspace hides the terminal on startup" });
    if (/"runOn"\s*:\s*"folderOpen"/.test(text)) out.push({ severity: "MEDIUM", kind: "settings", what: "workspace settings define a task that runs on folder open" });
  }
  if (base === ".gitignore" && [...WORM_FILES].some((w) => text.includes(w))) {
    out.push({ severity: "MEDIUM", kind: "gitignore", what: ".gitignore hides PolinRider propagation files (infector signature, or a defensive entry: review)" });
  }
  if (base === "package.json") {
    try {
      const scripts = JSON.parse(text).scripts || {};
      for (const k of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) {
        const v = String(scripts[k] || "");
        if (/setup_bun|bun_environment|(curl|wget)\s[^|]*\|\s*(ba|z)?sh/.test(v)) out.push({ severity: "HIGH", kind: "hulud", what: `package.json ${k} script downloads or runs a worm stage` });
      }
    } catch { /* not JSON */ }
  }
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(norm)) {
    if (/toJSON\(\s*secrets\s*\)/.test(text)) out.push({ severity: "HIGH", kind: "hulud", what: "workflow dumps all secrets (toJSON(secrets))" });
    if (/runs-on:\s*\[?\s*self-hosted/.test(text) && /\bdiscussion\b/.test(text)) out.push({ severity: "HIGH", kind: "hulud", what: "self-hosted workflow triggered by discussions (Shai-Hulud backdoor)" });
  }
  if (JS_EXT.has(ext)) {
    let hidden = false;
    for (const line of text.split("\n")) {
      PAD.lastIndex = 0;
      const m = PAD.exec(line);
      if (m && line.length - (m.index + m[0].length) >= 200) { hidden = true; break; }
    }
    const marked = MARKERS.some((re) => re.test(text));
    if (hidden || marked) out.push({ severity: "HIGH", kind: "loader", what: hidden ? "code hidden behind a long run of whitespace (PolinRider loader)" : "PolinRider marker in source" });
    else if (CONFIG_NAME.test(norm) && (text.match(OBF) || []).length >= 20) out.push({ severity: "MEDIUM", kind: "obfuscated", what: "heavily obfuscated identifiers in a config/route file" });
  }
  return out;
}

// ------------------------------------------------------------ working tree
function walk(dir, root, files) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !fs.existsSync(path.join(p, ".git"))) walk(p, root, files); }
    else if (e.isFile()) files.push(path.relative(root, p));
  }
}

function interesting(rel) {
  const base = path.basename(rel);
  const ext = path.extname(rel).toLowerCase();
  return JS_EXT.has(ext) || FONT_MAGIC[ext] || base === ".gitignore" || base === "package.json" || ext === ".code-workspace" ||
    rel.split(path.sep).join("/").match(/\.vscode\/(tasks|settings)\.json$|\.github\/workflows\//) || WORM_FILES.has(base) || HULUD_FILES.has(base);
}

function scanWorkingTree(repo) {
  const files = [];
  walk(repo, repo, files);
  for (const rel of files) {
    if (!interesting(rel)) continue;
    const abs = path.join(repo, rel);
    let buf;
    try { if (fs.statSync(abs).size > 50 * 1024 * 1024) continue; buf = fs.readFileSync(abs); } catch { continue; }
    const hits = classify(rel, buf);
    const sha = blobId(buf);
    if (isKnownBad(sha) && !hits.length) hits.push({ severity: "HIGH", kind: "known", what: `matches a known payload (blob ${sha.slice(0, 8)})` });
    for (const h of hits) {
      add(h.severity, "repo", `${repo}${path.sep}${rel}`, h.what, fixHint(h.kind));
      if (FIX) fixFile(repo, rel, abs, buf, h);
    }
  }
}

function fixHint(kind) {
  return {
    wormfile: "delete the file", hulud: "delete the file/script and rotate all tokens", fakefont: "delete the fake font",
    tasks: "delete .vscode/tasks.json", settings: 'set "task.allowAutomaticTasks": "off" and remove hideOnStartup/folderOpen tasks',
    gitignore: "remove the temp_*_push.bat / branch_structure.json lines unless you added them on purpose",
    loader: "restore the file to its content before the whitespace padding", known: "delete or restore the file", obfuscated: "review the file by hand",
  }[kind] || "review";
}

const fixed = new Set();
function fixFile(repo, rel, abs, buf, h) {
  if (fixed.has(abs)) return;
  const done = (msg) => { fixed.add(abs); actions.push(`${rel}: ${msg}`); };
  try {
    if (["wormfile", "fakefont", "known"].includes(h.kind) || (h.kind === "tasks" && h.severity === "HIGH") || (h.kind === "hulud" && HULUD_FILES.has(path.basename(rel)))) {
      fs.rmSync(abs, { force: true }); return done("deleted");
    }
    if (h.kind === "settings") {
      let text = buf.toString("utf8");
      try {
        const j = JSON.parse(text);
        j["task.allowAutomaticTasks"] = "off";
        if (j["terminal.integrated.hideOnStartup"] === "always") delete j["terminal.integrated.hideOnStartup"];
        if (j.tasks && JSON.stringify(j.tasks).includes("folderOpen")) delete j.tasks;
        text = JSON.stringify(j, null, 2) + "\n";
      } catch {
        text = text.replace(/("task\.allowAutomaticTasks"\s*:\s*)(true|"on")/, '$1"off"').replace(/"terminal\.integrated\.hideOnStartup"\s*:\s*"always"\s*,?/, "");
      }
      fs.writeFileSync(abs, text); return done("automatic tasks switched off");
    }
    if (h.kind === "loader") {
      const text = buf.toString("utf8");
      const lines = text.split("\n");
      for (let i = 0; i < lines.length; i++) {
        PAD.lastIndex = 0;
        const m = PAD.exec(lines[i]);
        if (m && lines[i].length - (m.index + m[0].length) >= 200) {
          const kept = lines.slice(0, i).concat(lines[i].slice(0, m.index).replace(/\s+$/, "")).join("\n").replace(/\s+$/, "") + "\n";
          fs.writeFileSync(abs, kept); return done(`hidden code after line ${i + 1} removed (check the file still works)`);
        }
      }
    }
    if (h.kind === "gitignore") return done("left as is (review by hand)");
  } catch (e) { actions.push(`${rel}: fix failed (${e.message})`); }
}

// ------------------------------------------------------------- git history
function scanHistory(repo) {
  const objs = git(repo, ["rev-list", "--all", "--objects"]);
  if (!objs.ok) return;
  const wanted = new Map();
  for (const line of objs.out.split("\n")) {
    const sp = line.indexOf(" ");
    if (sp < 0) continue;
    const sha = line.slice(0, sp); const p = line.slice(sp + 1);
    if (p.split("/").some((seg) => seg === "node_modules")) continue;
    if (interesting(p)) { if (!wanted.has(sha)) wanted.set(sha, new Set()); wanted.get(sha).add(p); }
  }
  if (!wanted.size) return;
  const check = sh("git", ["-C", repo, "cat-file", "--batch-check"], { input: [...wanted.keys()].join("\n") + "\n" });
  const small = [];
  for (const l of check.out.split("\n")) {
    const [sha, type, size] = l.split(" ");
    if (type === "blob" && Number(size) <= MAX_SCAN_BYTES) small.push(sha);
  }
  const bad = new Map();
  for (let i = 0; i < small.length; i += 2000) {
    const chunk = small.slice(i, i + 2000);
    const r = sh("git", ["-C", repo, "cat-file", "--batch"], { input: chunk.join("\n") + "\n", binary: true });
    let off = 0; const out = r.out;
    while (off < out.length) {
      const nl = out.indexOf(10, off); if (nl < 0) break;
      const [sha, type, size] = out.subarray(off, nl).toString().split(" ");
      const n = Number(size); const data = out.subarray(nl + 1, nl + 1 + n); off = nl + 1 + n + 1;
      if (type !== "blob") continue;
      const p = [...wanted.get(sha)][0];
      const hits = classify(p, data).filter((h) => h.severity === "HIGH");
      if (!hits.length && isKnownBad(sha)) hits.push({ what: "known payload blob" });
      if (hits.length) bad.set(sha, { paths: [...wanted.get(sha)], what: hits[0].what });
    }
  }
  // security/known-bad-history.txt: blob ids (one per line, # comments) of OLD infected objects that are still in
  // history and wait for a purge. They are reported as LOW instead of HIGH so CI stays usable. This never applies to
  // files at the tip of the working tree, and never to a blob that is not listed.
  const allow = [];
  try {
    for (const l of fs.readFileSync(path.join(repo, "security", "known-bad-history.txt"), "utf8").split("\n")) {
      const t = l.replace(/#.*/, "").trim();
      if (/^[0-9a-f]{7,40}$/i.test(t)) allow.push(t.toLowerCase());
    }
  } catch { /* none (bare repos have no working tree: use the committed copy) */ }
  if (!allow.length) {
    const r = git(repo, ["show", "HEAD:security/known-bad-history.txt"]);
    if (r.ok) for (const l of r.out.split("\n")) { const t = l.replace(/#.*/, "").trim(); if (/^[0-9a-f]{7,40}$/i.test(t)) allow.push(t.toLowerCase()); }
  }
  for (const [sha, info] of bad) {
    const listed = allow.some((a) => sha.startsWith(a));
    const first = git(repo, ["log", "--all", "-m", "--reverse", "--format=%h %an %ad", "--date=short", `--find-object=${sha}`]).out.split("\n")[0].trim();
    const tips = git(repo, ["for-each-ref", "--format=%(refname:short)", "--contains", first.split(" ")[0] || sha, "refs/heads", "refs/remotes"]).out.trim().split("\n").filter(Boolean);
    add(listed ? "LOW" : "HIGH", "history", `${repo} :: ${info.paths.join(", ")} (blob ${sha.slice(0, 8)})`, `${listed ? "KNOWN OLD INFECTED OBJECT, purge pending (listed in security/known-bad-history.txt); " : ""}${info.what}; introduced by ${first || "?"}; reachable from ${tips.length} ref(s)${tips.length ? ": " + tips.slice(0, 6).join(", ") + (tips.length > 6 ? ", ..." : "") : ""}`,
      "do not check these refs out or push them; ask the repo owner for a history purge (git filter-repo) and re-clone afterwards");
  }
  // Forged-amend heuristic: the worm copies the author timestamp into the committer field but stamps it UTC-7/-8.
  const log = git(repo, ["log", "--all", "-n", "3000", "--format=%h%x09%at%x09%ai%x09%cn%x09%ct%x09%ci%x09%s"]);
  let forged = 0;
  for (const l of log.out.split("\n")) {
    const [h, at, ai, cn, ct, ci, s] = l.split("\t");
    if (!h || cn === "GitHub") continue;
    if (looksForged(at, ai, ct, ci) && ++forged <= 15) {
      add("MEDIUM", "history", `${repo} :: commit ${h}`, `looks like a forged amend (committer "${cn}" ${ci.slice(-5)}, same second as the author): "${(s || "").slice(0, 60)}"`, "compare it with the original commit; worm amends add one config/font/.vscode change");
    }
  }
}

function looksForged(at, ai, ct, ci) {
  const az = (ai || "").slice(-5); const cz = (ci || "").slice(-5);
  return at === ct && az !== cz && /^-0[78]00$/.test(cz);
}

// ---------------------------------------------------------------- machine
function scanMachine() {
  // Processes
  let procs = [];
  if (PLATFORM === "win32") {
    const r = sh("powershell", ["-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"]);
    try { procs = JSON.parse(r.out || "[]").map((p) => ({ pid: p.ProcessId, cmd: p.CommandLine || "" })); } catch { /* ignore */ }
  } else {
    procs = sh("ps", ["-axo", "pid=,command="]).out.split("\n").map((l) => { const m = l.trim().match(/^(\d+)\s+(.*)$/); return m ? { pid: Number(m[1]), cmd: m[2] } : null; }).filter(Boolean);
  }
  const PROC_BAD = [
    [ASSET_RUN, "node is running a font/image file (PolinRider payload)"],
    [/\b(bun|node)\s+[^\s]*(setup_bun|bun_environment)\.js/, "Shai-Hulud stage running"],
    [/trufflehog/i, "trufflehog running (Shai-Hulud secret harvesting)"],
    [/Runner\.Listener|actions-runner\/run|SHA1HULUD/i, "GitHub self-hosted runner (Shai-Hulud backdoor)"],
    [/osascript[^\n]*the clipboard|while[^\n]*pbpaste/, "clipboard polling (crypto-address swapper)"],
  ];
  for (const p of procs) {
    if (p.pid === process.pid || /selfcheck\.mjs/.test(p.cmd)) continue;
    for (const [re, what] of PROC_BAD) {
      if (re.test(p.cmd)) {
        add("HIGH", "machine", `process ${p.pid}: ${p.cmd.slice(0, 140)}`, what, PLATFORM === "win32" ? `taskkill /PID ${p.pid} /F` : `kill -9 ${p.pid}`);
        if (FIX && re === ASSET_RUN) { try { process.kill(p.pid, "SIGKILL"); actions.push(`killed process ${p.pid}`); } catch (e) { actions.push(`could not kill ${p.pid}: ${e.message}`); } }
      }
    }
  }
  // Editor user settings
  const appData = process.env.APPDATA || path.join(HOME, "AppData", "Roaming");
  const editorRoots = PLATFORM === "darwin" ? path.join(HOME, "Library", "Application Support") : PLATFORM === "win32" ? appData : path.join(HOME, ".config");
  for (const ed of ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium", "Kiro", "Antigravity"]) {
    const f = path.join(editorRoots, ed, "User", "settings.json");
    if (!fs.existsSync(f)) continue;
    const text = fs.readFileSync(f, "utf8");
    const m = text.match(/"task\.allowAutomaticTasks"\s*:\s*("?[\w]+"?)/);
    if (!m || m[1] !== '"off"') {
      add(m && /true|"on"/.test(m[1]) ? "HIGH" : "MEDIUM", "machine", f, `${ed}: automatic tasks are ${m ? m[1] : "not explicitly off"}`, 'set "task.allowAutomaticTasks": "off" in user settings');
      if (FIX) {
        const next = m ? text.replace(/("task\.allowAutomaticTasks"\s*:\s*)("?[\w]+"?)/, '$1"off"') : text.replace(/^\s*\{/, '{\n  "task.allowAutomaticTasks": "off",');
        if (next !== text) { fs.writeFileSync(f, next); actions.push(`${ed} user settings: automatic tasks off`); }
      }
    }
    for (const t of ["tasks.json"]) {
      const tf = path.join(editorRoots, ed, "User", t);
      if (fs.existsSync(tf) && /"runOn"\s*:\s*"folderOpen"/.test(fs.readFileSync(tf, "utf8"))) add("HIGH", "machine", tf, `${ed}: user-level task runs on every folder open`, "remove the folderOpen task");
    }
  }
  // Persistence
  const suspicious = (s) => ASSET_RUN.test(s) || /base64\s+(-d|--decode)|curl[^\n]*\|\s*(ba|z)?sh|setup_bun|bun_environment|trufflehog|\/tmp\/[^\s<]*\.(js|sh)|pbpaste/.test(s);
  if (PLATFORM === "darwin") {
    for (const d of [path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]) {
      let list = []; try { list = fs.readdirSync(d).filter((f) => f.endsWith(".plist")); } catch { continue; }
      for (const f of list) {
        const p = path.join(d, f);
        const xml = sh("plutil", ["-convert", "xml1", "-o", "-", p]).out;
        if (suspicious(xml)) add("HIGH", "machine", p, "launch item starts a suspicious command", `launchctl bootout gui/$(id -u) '${p}' && rm '${p}'   (review first)`);
      }
    }
  } else if (PLATFORM === "linux") {
    const cron = sh("crontab", ["-l"]).out;
    if (suspicious(cron)) add("HIGH", "machine", "crontab", "cron job runs a suspicious command", "crontab -e and remove it");
    for (const d of [path.join(HOME, ".config/autostart"), path.join(HOME, ".config/systemd/user")]) {
      let list = []; try { list = fs.readdirSync(d); } catch { continue; }
      for (const f of list) { const p = path.join(d, f); try { if (suspicious(fs.readFileSync(p, "utf8"))) add("HIGH", "machine", p, "autostart entry runs a suspicious command", `remove ${p}`); } catch { /* dir */ } }
    }
  } else if (PLATFORM === "win32") {
    for (const key of ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]) {
      const out = sh("reg", ["query", key]).out;
      for (const l of out.split("\n")) if (suspicious(l) || /powershell[^\n]*-enc/i.test(l)) add("HIGH", "machine", key, `run key: ${l.trim().slice(0, 120)}`, `reg delete "${key}" /v <name>`);
    }
    const startup = path.join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
    try { for (const f of fs.readdirSync(startup)) if (/\.(bat|cmd|vbs|js|ps1)$/i.test(f)) add("MEDIUM", "machine", path.join(startup, f), "script in the Startup folder", "review and remove if unknown"); } catch { /* none */ }
    const tasks = sh("schtasks", ["/query", "/fo", "csv", "/v"]).out;
    for (const l of tasks.split("\n")) if (suspicious(l) || /powershell[^\n]*-enc/i.test(l)) add("HIGH", "machine", "scheduled task", l.slice(0, 160), "schtasks /delete /tn <name>");
  }
  // Worm folders in the home directory
  for (const d of [".truffler-cache", ".dev-env", "actions-runner"]) {
    if (fs.existsSync(path.join(HOME, d))) add("HIGH", "machine", path.join(HOME, d), "Shai-Hulud working folder", "delete it after rotating every token on this machine");
  }
  // Git and npm hygiene (informational)
  const hooks = sh("git", ["config", "--global", "--get", "core.hooksPath"]).out.trim();
  const tmpl = sh("git", ["config", "--global", "--get", "init.templateDir"]).out.trim();
  if (hooks) add("LOW", "machine", "git config --global core.hooksPath", `global hooks folder is ${hooks}`, "make sure every hook in it is yours");
  if (tmpl) add("LOW", "machine", "git config --global init.templateDir", `template folder is ${tmpl}`, "make sure its hooks are yours");
  const ign = sh(PLATFORM === "win32" ? "npm.cmd" : "npm", ["config", "get", "ignore-scripts"]).out.trim();
  if (ign && ign !== "true") add("LOW", "machine", "npm config ignore-scripts", "npm runs install scripts of every dependency", "npm config set ignore-scripts true (re-enable per project only when a package needs it)");
}

// ------------------------------------------------------------- hook mode
function prePush(repo) {
  const input = fs.readFileSync(0, "utf8");
  const zero = /^0+$/;
  for (const line of input.split("\n")) {
    const [, localSha] = line.trim().split(/\s+/);
    if (!localSha || zero.test(localSha)) continue;
    const commits = git(repo, ["rev-list", localSha, "--not", "--remotes"]).out.split("\n").filter(Boolean);
    for (const c of commits) {
      const tree = git(repo, ["diff-tree", "-r", "--no-commit-id", "--root", "-m", c]).out;
      for (const l of tree.split("\n")) {
        const m = l.match(/^:\d+ \d+ [0-9a-f]+ ([0-9a-f]+) [AMT]\t(.+)$/);
        if (!m || !interesting(m[2])) continue;
        const data = git(repo, ["cat-file", "blob", m[1]], { binary: true }).out;
        for (const h of classify(m[2], data).filter((x) => x.severity === "HIGH")) add("HIGH", "push", `${c.slice(0, 8)} ${m[2]}`, h.what, "do not push; run node security/selfcheck.mjs --fix and recommit");
        if (isKnownBad(m[1])) add("HIGH", "push", `${c.slice(0, 8)} ${m[2]}`, "known payload blob", "do not push");
      }
      const [at, ai, cn, ct, ci] = git(repo, ["log", "-1", "--format=%at%x09%ai%x09%cn%x09%ct%x09%ci", c]).out.trim().split("\t");
      if (cn !== "GitHub" && looksForged(at, ai, ct, ci)) {
        add("HIGH", "push", c.slice(0, 8), "commit looks like a worm amend (committer time copied from the author, UTC-7/-8)", "do not push; check where this commit came from");
      }
    }
  }
}

function installHook(repo) {
  const hooksDir = git(repo, ["rev-parse", "--git-path", "hooks"]).out.trim();
  const dir = path.isAbsolute(hooksDir) ? hooksDir : path.join(repo, hooksDir);
  const f = path.join(dir, "pre-push");
  const body = '#!/bin/sh\n# solutionplus selfcheck pre-push guard\nexec node "$(git rev-parse --show-toplevel)/security/selfcheck.mjs" --pre-push "$@"\n';
  if (fs.existsSync(f) && !fs.readFileSync(f, "utf8").includes("solutionplus selfcheck")) {
    console.log(`A different pre-push hook already exists at ${f}. Add this line to it:\n  node "$(git rev-parse --show-toplevel)/security/selfcheck.mjs" --pre-push "$@" || exit 1`);
    return;
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(f, body, { mode: 0o755 });
  console.log(`pre-push guard installed at ${f}`);
}

// ------------------------------------------------------------------ main
function repoRoot(start) {
  const r = git(start, ["rev-parse", "--show-toplevel"]);
  if (r.ok) return r.out.trim();
  const b = git(start, ["rev-parse", "--is-bare-repository"]);
  return b.ok && b.out.trim() === "true" ? path.resolve(start) : null;
}

function findRepos(dir, out, depth = 0) {
  if (depth > 6) return;
  let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  if (entries.some((e) => e.name === ".git")) { out.push(dir); return; }
  for (const e of entries) if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) findRepos(path.join(dir, e.name), out, depth + 1);
}

try {
  const start = path.resolve(opt("--repo") || process.cwd());
  if (flag("--pre-push")) {
    const root = repoRoot(start);
    prePush(root);
    if (findings.length) {
      console.error("\nsecurity/selfcheck.mjs blocked this push:");
      for (const f of findings) console.error(`  [${f.severity}] ${f.where}: ${f.what}`);
      process.exit(1);
    }
    process.exit(0);
  }
  if (flag("--install-hook")) { const root = repoRoot(start); if (!root) throw new Error("not inside a git repo"); installHook(root); process.exit(0); }

  const repos = [];
  const scanDir = opt("--scan-dir");
  if (scanDir) findRepos(path.resolve(scanDir.replace(/^~(?=$|\/)/, HOME)), repos);
  else { const root = repoRoot(start); if (root) repos.push(root); }
  for (const repo of repos) {
    const bare = git(repo, ["rev-parse", "--is-bare-repository"]).out.trim() === "true";
    if (!bare) scanWorkingTree(repo);
    if (DO_HISTORY) scanHistory(repo);
  }
  if (DO_MACHINE) scanMachine();

  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const high = findings.filter((f) => f.severity === "HIGH").length;
  if (JSON_OUT) {
    console.log(JSON.stringify({ version: VERSION, repos, high, findings, actions }, null, 2));
  } else {
    if (!QUIET) console.log(`SolutionPlus security self-check ${VERSION} - ${repos.length} repo(s)${DO_MACHINE ? " + this machine" : ""}${FIX ? " - FIX MODE" : ""}`);
    if (!findings.length) console.log("CLEAN: no PolinRider / Shai-Hulud indicators found.");
    for (const f of findings) console.log(`\n[${f.severity}] ${f.area}: ${f.where}\n    ${f.what}${f.fix ? `\n    fix: ${f.fix}` : ""}`);
    if (actions.length) { console.log("\nActions taken:"); for (const a of actions) console.log(`  - ${a}`); }
    if (high) {
      console.log(`\n${high} HIGH finding(s). AGENT ACTION REQUIRED: stop normal work and follow security/AGENT_SECURITY_RULES.md`);
      console.log("  1) do not open this folder in VS Code/Cursor and do not push anything");
      console.log("  2) run: node security/selfcheck.mjs --fix   then run it again until it is clean");
      console.log("  3) rotate GitHub/npm/cloud tokens used on this machine and tell the repo owner (Saif)");
    }
  }
  process.exit(high ? 1 : 0);
} catch (e) {
  console.error(`selfcheck failed: ${e.stack || e.message}`);
  process.exit(2);
}
