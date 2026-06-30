// Project-trust gate. Project-scope config (cwd/.pi/providers/...) must not be
// read or written until the user has trusted the project for this session.
// Mirrors the pattern in pi-provider-kimi-code so behavior is consistent.

export async function isPhalaProjectConfigApproved(
  ctx: unknown,
  cwd: string,
): Promise<boolean> {
  const check = (ctx as { isProjectTrusted?: () => boolean } | undefined)?.isProjectTrusted;
  if (typeof check !== "function") return true;

  let sessionTrusted: boolean;
  try {
    sessionTrusted = check.call(ctx);
  } catch {
    return false;
  }
  if (!sessionTrusted) return false;

  const mod = (await import("@earendil-works/pi-coding-agent")) as unknown as {
    ProjectTrustStore?: new (agentDir: string) => { get(cwd: string): boolean | null };
    getAgentDir?: () => string;
  };
  if (!mod.ProjectTrustStore || !mod.getAgentDir) return true;

  try {
    return new mod.ProjectTrustStore(mod.getAgentDir()).get(cwd) === true;
  } catch {
    return false;
  }
}
