# Agent security rules (mandatory)

These rules apply to every AI coding agent working in a SolutionPlus repository
(Claude Code, Codex, Cursor, Copilot, Antigravity/Gemini, or any other) and to
the humans driving them. They exist because of a real incident.

## Why

Between June and September 2026, the **PolinRider / EtherHiding** worm infected
the laptops of several SolutionPlus developers. From each infected machine it:

- appended hidden JavaScript to config files (`babel.config.js`,
  `postcss.config.mjs`, `eslint.config.js`, `tailwind.config.js`, even
  `src/routes/routes.js`), padded with whitespace so the code sits far to the
  right of the visible text;
- added `.vscode/tasks.json` with a hidden task that runs on folder open
  (`node ./public/fonts/fa-solid-400.woff2`), where the "font" is JavaScript;
- set `"task.allowAutomaticTasks": true` and hid the terminal in
  `.vscode/settings.json`;
- amended real commits, copying author name, date and message, and
  force-pushed them to every branch with the developer's own GitHub
  credentials.

Opening an infected repo in VS Code or Cursor was enough to run it. The
payload reads Ethereum RPC endpoints, steals clipboard crypto addresses and
spreads on. We also check for **Shai-Hulud** (an npm worm that runs
`setup_bun.js` / `bun_environment.js` and `trufflehog`, and registers
self-hosted GitHub runners).

## 1. Before doing anything else in a repo

Run the self-check from the repo root:

```sh
node security/selfcheck.mjs
```

- Exit code `0`: clean. Carry on.
- Exit code `1`: **stop all normal work** and follow section 2.
- Exit code `2`: the check itself failed. Tell the user and do not continue.

Run it again before every commit you make and before every push.

## 2. If the self-check reports HIGH findings

1. Do not open the folder in VS Code or Cursor, do not run `npm install`,
   `npm run`, builds or tests, and **do not commit or push anything**.
2. Tell the user exactly what was found.
3. With the user's agreement, run `node security/selfcheck.mjs --fix`. It
   deletes loader tasks, fake fonts and worm files, switches editor
   auto-tasks off, strips the hidden code from config files, and kills a
   process that is running a font file. It never touches git history or the
   remote.
4. Run `node security/selfcheck.mjs` again. Repeat until it is clean.
5. Check the whole machine, not just this repo:
   `node security/selfcheck.mjs --scan-dir ~` (or the folder holding all your
   code). Fix every repo it reports.
6. If anything was found on the machine (processes, launch items, scheduled
   tasks, run keys), remove it with the commands the report prints, after
   showing them to the user.
7. **Rotate credentials** used on that machine: GitHub (personal access
   tokens, OAuth apps, `gh auth refresh`, SSH keys), npm tokens, cloud keys
   (AWS, GCP, Supabase, Vercel), `.env` secrets of every project opened on it.
8. Tell the repo owner (Saif Qureshi). Infected **history** cannot be fixed
   locally; it needs a coordinated `git filter-repo` purge and a re-clone.
9. Install the push guard: `node security/selfcheck.mjs --install-hook`.

## 3. Rules that always apply

- Never set `task.allowAutomaticTasks` to anything but `"off"`. Never commit
  `.vscode/tasks.json`. The org blocks pushes containing it.
- Never commit files under `public/fonts/` (or any font) unless they are real
  fonts you added on purpose.
- Read every diff to a config file (`*.config.*`, `babel`, `postcss`,
  `tailwind`, `eslint`, `metro`, `next`, `vite`, `webpack`) before
  committing. Scroll right: a line that continues after a long run of spaces
  is an attack.
- Never force-push and never amend or rebase commits that are already pushed.
  The org rejects force-pushes on every branch.
- Install dependencies with scripts disabled where possible
  (`npm ci --ignore-scripts`, or `npm config set ignore-scripts true`). Add new
  dependencies only with exact versions and only when needed.
- Never run scripts, binaries or `npx` packages from unknown sources, and
  never pipe `curl`/`wget` into a shell.
- Never write a suspicious file's content to disk, never execute it, and never
  paste it into chat. Inspect it only through commands that print sizes,
  hashes or short markers.
- Never print, copy or commit secrets, tokens or `.env` files.
- If you see a commit whose committer is a first name only, stamped `-0700`
  or `-0800` at exactly the author's time, treat it as a worm amend and
  report it.

## 4. Commands

```sh
node security/selfcheck.mjs                    # repo + history + this machine
node security/selfcheck.mjs --fix              # neutralise what it finds
node security/selfcheck.mjs --scan-dir ~/code  # every repo under a folder
node security/selfcheck.mjs --install-hook     # block infected pushes locally
node security/selfcheck.mjs --ci               # what CI runs
```

CI runs the same check on every push and pull request
(`.github/workflows/security-selfcheck.yml`). A red check means: do not merge.

## 5. Repos whose history is not purged yet

Some repositories still carry old infected objects in their git history
(they are rewritten later, in an agreed freeze window, because rewriting
breaks every open pull request and clone). Their blob ids are listed in
`security/known-bad-history.txt`; the self-check reports them as `LOW` so CI
stays green and people keep reading the output.

- Nothing is ever added to that file for a file that exists in the current
  working tree. Those are always HIGH.
- Do not check out or build very old commits of these repos, and never copy
  a file from old history into the working tree.
- Never add entries to `known-bad-history.txt` yourself to silence a
  failure. Only the repo owner does, after verifying the blob is old history.

