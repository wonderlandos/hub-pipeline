// SPDX-License-Identifier: GPL-2.0-or-later
// Who a GitHub id is, asked of GitHub itself by the ca job (audit-1 H2): the certificate names the login and display name
// GitHub gives for the signed github_id, never what the Worker's request record says. Read-only: GET requests with the
// job's own token (CA_GITHUB_TOKEN, else GITHUB_TOKEN).
//
//   user(id)                 -> {id, login, name, type} | null       GET /user/{id}
//   org(id)                  -> {id, login, name, type} | null       GET /organizations/{id}
//   publicMember(org, login) -> true|false                          GET /orgs/{org}/public_members/{login} (204 = yes)
//   role(org, login)         -> "admin"|"member"|null               GET /orgs/{org}/memberships/{login} (needs members:read on that org)
//
// With a fixture (HUB_TEST=1 only): the "users", "orgs", "public_members" and "memberships" maps of fixtures/github.json.
import { readJson } from "./lib.mjs";

const API = "https://api.github.com";

export function githubIdentity(fixturePath) {
  if (fixturePath) {
    if (process.env.HUB_TEST !== "1") throw new Error("--github-fixture is for local dry runs (HUB_TEST=1)");
    const fx = readJson(fixturePath);
    return {
      user: async (id) => fx.users?.[id] ?? null,
      org: async (id) => fx.orgs?.[id] ?? null,
      publicMember: async (org, login) => (fx.public_members?.[org.toLowerCase()] ?? []).some((l) => l.toLowerCase() === login.toLowerCase()),
      role: async (org, login) => fx.memberships?.[`${org.toLowerCase()}/${login.toLowerCase()}`] ?? null,
    };
  }
  const token = process.env.CA_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  const call = async (path) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt) await new Promise((r) => setTimeout(r, 2000 * attempt));
      try {
        const res = await fetch(`${API}${path}`, {
          headers: { accept: "application/vnd.github+json", "x-github-version": "2022-11-28", "user-agent": "wolos-hub-index-ca", ...(token ? { authorization: `Bearer ${token}` } : {}) },
          signal: AbortSignal.timeout(30_000),
        });
        if (res.status === 404 || res.status === 403 || res.status === 302) return { status: res.status, data: null };
        if (res.ok) return { status: res.status, data: res.status === 204 ? true : await res.json() };
      } catch {
        /* try again */
      }
    }
    throw new Error(`GitHub did not answer ${path}`);
  };
  const who = (d) => (d ? { id: d.id, login: d.login, name: d.name ?? null, type: d.type } : null);
  return {
    user: async (id) => who((await call(`/user/${Number(id)}`)).data),
    org: async (id) => who((await call(`/organizations/${Number(id)}`)).data),
    publicMember: async (org, login) => (await call(`/orgs/${encodeURIComponent(org)}/public_members/${encodeURIComponent(login)}`)).status === 204,
    role: async (org, login) => {
      const r = await call(`/orgs/${encodeURIComponent(org)}/memberships/${encodeURIComponent(login)}`);
      return r.data && r.data.state === "active" ? r.data.role : null;
    },
  };
}
