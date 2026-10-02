# Agent instructions

<!-- solutionplus-security:start -->
## Security self-check (mandatory, every agent, every session)

This organisation was hit by the PolinRider worm (hidden code in config files,
`.vscode/tasks.json` auto-run loaders, forged force-pushes). Before any other
work in this repo:

1. Run `node security/selfcheck.mjs`. If it exits non-zero, stop, tell the
   user, and follow `security/AGENT_SECURITY_RULES.md` (`--fix`, machine scan,
   credential rotation). Do not commit or push until it is clean.
2. Run it again before every commit and push.
3. Never enable `task.allowAutomaticTasks`, never commit `.vscode/tasks.json`
   or fake fonts, never force-push or amend pushed commits, install
   dependencies with `--ignore-scripts` where possible, and read every config
   file diff to its right edge.

Full rules: `security/AGENT_SECURITY_RULES.md`.
<!-- solutionplus-security:end -->
