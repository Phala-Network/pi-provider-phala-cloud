// Open a URL in the system browser without invoking a shell.
//
// Mirrors pi's internal open-browser util (not exported from the public
// API): on Windows, do not use `cmd /c start` — cmd.exe re-parses
// metacharacters (&, |, ^, ...) before `start` runs, which would make an
// attacker-controlled URL injectable.

import { spawn } from "node:child_process";

export function openExternalUrl(target: string): void {
  const [cmd, args] =
    process.platform === "darwin"
      ? ["open", [target]]
      : process.platform === "win32"
        ? ["rundll32", ["url.dll,FileProtocolHandler", target]]
        : ["xdg-open", [target]];
  // Launcher failures (e.g. missing xdg-open) arrive as an error event; the
  // caller still shows the URL to the user, so keep them from crashing pi.
  spawn(cmd, args, { stdio: "ignore", detached: true, cwd: "/" })
    .on("error", () => {})
    .unref();
}
