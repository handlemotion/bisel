// The bisel dashboard: sign up / sign in with a passkey, see the box and its devices, delete the box.
// Plain DOM, no framework. Text from the server is only ever assigned through textContent.
import { createAuthClient } from "better-auth/client";
import { passkeyClient } from "@better-auth/passkey/client";

const auth = createAuthClient({ plugins: [passkeyClient()] });
const root = document.getElementById("app")!;

type Child = Node | string | null | false;
function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...kids: Child[]) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const kid of kids) if (kid) el.append(kid);
  return el;
}

interface Device {
  id: string;
  name: string;
  kind: string;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
  activates_at: number | null;
}
interface BoxState {
  user: { id: string; name: string };
  box: { id: string; created_at: number; epoch: number; head_seq: number; item_count: number } | null;
  devices: Device[];
}

const api = async (method: string, path: string, body?: unknown) => {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "X-Bisel-CSRF": "1", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json: json as any };
};

const day = (t: number) => new Date(t * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
const errorText = (e: unknown) => (e instanceof Error ? e.message : typeof e === "string" ? e : "Something went wrong.");

async function guarded(button: HTMLButtonElement, out: HTMLElement, work: () => Promise<void>) {
  button.disabled = true;
  out.textContent = "";
  try {
    await work();
  } catch (e) {
    out.textContent = errorText(e);
  } finally {
    button.disabled = false;
  }
}

/** better-auth client calls resolve to { data, error } instead of throwing. */
function must<T>(r: { data: T | null; error: { message?: string } | null }): T {
  if (r.error || r.data === null) throw new Error(r.error?.message || "That did not work. Try again.");
  return r.data;
}

// ---------------------------------------------------------------------------------------------------------------------
// signed out

function authForms(afterSignIn: () => void): HTMLElement {
  const name = h("input", { type: "text", id: "name", name: "name", autocomplete: "nickname", maxlength: "40", placeholder: "Your name, for example Rodrigo" });
  const createOut = h("p", { class: "error", role: "alert" });
  const create = h("button", { class: "primary", type: "button" }, "Create account with a passkey");
  create.addEventListener("click", () =>
    guarded(create, createOut, async () => {
      const value = name.value.trim();
      if (!value) throw new Error("Enter a name first.");
      must(await auth.passkey.addPasskey({ name: "First passkey", context: value }));
      afterSignIn();
    }),
  );
  const signOut = h("p", { class: "error", role: "alert" });
  const signIn = h("button", { type: "button" }, "Sign in with a passkey");
  signIn.addEventListener("click", () =>
    guarded(signIn, signOut, async () => {
      must(await auth.signIn.passkey());
      afterSignIn();
    }),
  );
  return h(
    "div",
    {},
    h("div", { class: "card stack" },
      h("h1", {}, "Create an account"),
      h("p", {}, "A passkey is your sign-in. Your passwords stay encrypted on your devices; this server only holds ciphertext."),
      h("label", { for: "name", class: "pill" }, "Name"),
      name,
      create,
      createOut,
    ),
    h("div", { class: "card stack" }, h("h1", {}, "Already have one?"), signIn, signOut),
  );
}

// ---------------------------------------------------------------------------------------------------------------------
// signed in

async function passkeyList(): Promise<HTMLElement> {
  const card = h("div", { class: "card" });
  const out = h("p", { class: "error", role: "alert" });
  const render = async () => {
    const keys = (must(await auth.passkey.listUserPasskeys()) as { id: string; name?: string | null; createdAt?: string | Date | null }[]) ?? [];
    const list = h("ul", { class: "list" });
    for (const k of keys) {
      const remove = h("button", { type: "button" }, "Remove");
      remove.disabled = keys.length < 2;
      remove.addEventListener("click", () =>
        guarded(remove, out, async () => {
          must(await auth.passkey.deletePasskey({ id: k.id }));
          await render();
        }),
      );
      list.append(h("li", {}, h("span", {}, k.name || "Passkey"), h("span", { class: "meta" }, k.createdAt ? new Date(k.createdAt).toLocaleDateString() : ""), remove));
    }
    const add = h("button", { type: "button" }, "Add another passkey");
    add.addEventListener("click", () =>
      guarded(add, out, async () => {
        must(await auth.passkey.addPasskey({ name: `Passkey ${keys.length + 1}` }));
        await render();
      }),
    );
    card.replaceChildren(list, h("div", { class: "row" }, add), out);
    if (keys.length < 2) card.append(h("p", {}, "Add a second passkey so losing one does not lock you out of this page. Your devices keep syncing either way."));
  };
  await render();
  return card;
}

function deviceList(devices: Device[]): HTMLElement {
  const list = h("ul", { class: "list" });
  for (const d of devices) {
    const status = d.revoked_at ? `revoked ${day(d.revoked_at)}` : d.last_seen_at ? `seen ${day(d.last_seen_at)}` : `added ${day(d.created_at)}`;
    list.append(h("li", {}, h("span", {}, d.name, " ", h("span", { class: "pill" }, d.kind)), h("span", { class: "meta" }, status)));
  }
  return h("div", { class: "card" }, list);
}

function deleteBox(afterDelete: () => void): HTMLElement {
  const out = h("p", { class: "error", role: "alert" });
  const button = h("button", { class: "danger", type: "button" }, "Delete box from the server");
  button.addEventListener("click", () =>
    guarded(button, out, async () => {
      if (!window.confirm("Delete this box from the server? Devices keep their local copy, but nothing will sync until you create a new box.")) return;
      // Deleting needs a passkey sign-in from the last few minutes.
      must(await auth.signIn.passkey());
      const res = await api("DELETE", "/api/box", { confirm: "delete" });
      if (res.status !== 200) throw new Error(res.json.error === "reauth_required" ? "Sign in again, then retry." : "Could not delete the box.");
      afterDelete();
    }),
  );
  return h("div", { class: "card stack" }, h("p", {}, "Removes the encrypted copy of your box from this server. The apps on your devices are not touched."), button, out);
}

async function dashboard(state: BoxState, rerender: () => void): Promise<HTMLElement> {
  const signOut = h("button", { type: "button" }, "Sign out");
  signOut.addEventListener("click", async () => {
    await auth.signOut();
    rerender();
  });
  const page = h("div", {}, h("div", { class: "row" }, h("h1", {}, state.user.name), signOut));
  if (state.box) {
    page.append(
      h("h2", {}, "Box"),
      h("div", { class: "card" }, h("p", {}, `Created ${day(state.box.created_at)} · ${state.box.item_count} items · key epoch ${state.box.epoch}`)),
      h("h2", {}, "Devices"),
      deviceList(state.devices),
    );
  } else {
    page.append(
      h("h2", {}, "Box"),
      h("div", { class: "card" }, h("p", {}, "No box yet. Open bisel on your Mac, go to Settings, and choose Sync. It will open this site to connect.")),
    );
  }
  page.append(h("h2", {}, "Passkeys"), await passkeyList());
  if (state.box) page.append(h("h2", {}, "Danger"), deleteBox(rerender));
  return page;
}

// ---------------------------------------------------------------------------------------------------------------------
// /connect?code=ABCD-EFGH : the person approves what their Mac asked for

interface ConnectInfo {
  kind: "create" | "claim";
  device_name: string;
  country: string | null;
  created_at: number;
  account_has_box: boolean;
}

function connectCard(info: ConnectInfo, code: string, done: (message: string) => void): HTMLElement {
  const out = h("p", { class: "error", role: "alert" });
  const claim = info.kind === "claim";
  const blocked = info.account_has_box;
  const approve = h("button", { class: "primary", type: "button" }, blocked && !claim ? "Tell my Mac" : claim ? "Link this box" : "Approve");
  approve.addEventListener("click", () =>
    guarded(approve, out, async () => {
      const res = await api("POST", "/api/connect/approve", { code });
      if (res.status === 409) throw new Error(res.json.error === "box_exists" ? "This account already has a box." : "That box is already linked to an account.");
      if (res.status !== 200) throw new Error("This code is no longer valid. Start again from bisel on your Mac.");
      done(
        blocked && !claim
          ? "Your Mac has been told. It will explain how to add itself to your existing box."
          : claim
            ? "Linked. Your box now belongs to this account."
            : "Approved. Go back to bisel on your Mac; it continues by itself.",
      );
    }),
  );
  const deny = h("button", { type: "button" }, "Not me");
  deny.addEventListener("click", () =>
    guarded(deny, out, async () => {
      await api("POST", "/api/connect/deny", { code });
      done("Cancelled. Nothing was connected.");
    }),
  );
  const where = info.country ? ` Requested from ${info.country}.` : "";
  return h(
    "div",
    { class: "card stack" },
    h("h1", {}, claim ? `Link “${info.device_name}” to your account` : `Connect “${info.device_name}”`),
    h("p", {}, `Your Mac should be showing this code.${where} Only continue if they match.`),
    h("div", { class: "code" }, code),
    blocked && !claim ? h("p", {}, "This account already has a box, so this Mac cannot create another one.") : null,
    blocked && claim ? h("p", {}, "This account already has a box, so another cannot be linked.") : null,
    h("div", { class: "row" }, deny, blocked && claim ? null : approve),
    out,
  );
}

async function connectPage(): Promise<void> {
  const raw = new URLSearchParams(location.search).get("code") ?? "";
  const code = raw.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^(.{4})(.*)$/, "$1-$2");
  const title = h("h1", {}, "Connect your Mac");
  const me = await api("GET", "/api/box");
  if (me.status === 401) {
    root.replaceChildren(title, h("p", {}, "Sign in, or create an account, to approve the connection."), authForms(() => void connectPage()));
    return;
  }
  const res = await api("GET", `/api/connect?code=${encodeURIComponent(code)}`);
  if (res.status !== 200) {
    root.replaceChildren(
      h("div", { class: "card stack" }, h("h1", {}, "That code is not valid"), h("p", {}, "It may have expired or already been used. Start again from bisel on your Mac.")),
    );
    return;
  }
  const dashboardLink = h("a", { href: "/" }, "Open your dashboard");
  root.replaceChildren(
    connectCard(res.json as ConnectInfo, code, (message) =>
      root.replaceChildren(h("div", { class: "card stack" }, h("h1", {}, "Done"), h("p", {}, message), dashboardLink)),
    ),
  );
}

// ---------------------------------------------------------------------------------------------------------------------

async function render() {
  if (location.pathname === "/connect") return connectPage();
  const res = await api("GET", "/api/box");
  if (res.status === 401) {
    root.replaceChildren(h("h1", {}, "bisel"), authForms(render));
    return;
  }
  if (res.status !== 200) {
    root.replaceChildren(h("h1", {}, "bisel"), h("p", { class: "error" }, "The server could not be reached."));
    return;
  }
  root.replaceChildren(await dashboard(res.json as BoxState, render));
}

void render();
