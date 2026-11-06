// The extension's only link to Bisel. Native messages: docs/SPEC.md §8, "Chrome extension". `save.*` today; `fill.*` would be new types.

export type PageMessage =
  | { type: "submitted"; username: string; password: string }
  | { type: "pending" };
export type PromptMessage = { type: "prompt" } | { type: "answer"; accept: boolean };

export interface PromptView {
  host: string;
  username: string;
  action: "save" | "update";
  /** Replaces the login line after an attempt that did not go through. */
  note?: string;
}

interface Pending {
  site: string;
  username: string;
  password: string;
  action: "save" | "update";
  until: number;
}

interface NativeReply {
  result?: string;
  error?: string;
}

export const HOST_NAME = "app.bisel.browser";
const VERSION = 1;
const LIFETIME_MS = 120_000;
const MAX_FIELD = 4096;

/** The parts of `chrome` the worker uses, so the flows can run without a browser. */
export interface Browser {
  extensionID: string;
  promptURL: string;
  sendNative(message: object): Promise<NativeReply>;
  closePrompt(tabID: number): void;
  session: {
    get(key: string): Promise<Pending | undefined>;
    set(key: string, value: Pending): Promise<void>;
    remove(key: string): Promise<void>;
    keys(): Promise<string[]>;
  };
  scheduleSweep(): void;
  now(): number;
}

type Sender = chrome.runtime.MessageSender;

const pendingKey = (tabID: number): string => `pending:${tabID}`;

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** The password stays here until the person accepts: the check sends a salted hash of it. */
async function saltedDigest(password: string): Promise<{ salt: string; digest: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const typed = new TextEncoder().encode(password);
  const joined = new Uint8Array(salt.length + typed.length);
  joined.set(salt);
  joined.set(typed, salt.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
  return { salt: base64(salt), digest: base64(digest) };
}

export function createWorker(browser: Browser) {
  /** Sign-ins being checked, so the page after a navigation waits for the one before it. */
  const checks = new Map<number, Promise<void>>();

  const native = async (message: object): Promise<NativeReply> => {
    try {
      return await browser.sendNative({ v: VERSION, id: crypto.randomUUID(), ...message });
    } catch {
      return { error: "app_not_running" };
    }
  };

  /** The top frame of an https page in a tab of this profile. Chrome says so, not the page: a frame's own claim is never read. */
  const pageTab = (sender: Sender): { tabID: number; site: string } | null => {
    const tabID = sender.tab?.id;
    const origin = sender.origin;
    if (sender.id !== browser.extensionID || tabID === undefined || sender.frameId !== 0) {
      return null;
    }
    if (origin === undefined || !origin.startsWith("https://")) return null;
    return { tabID, site: origin };
  };

  /** Only prompt.html can answer. A content script, and so a page that broke out of its renderer sandbox into one, is never this. */
  const promptTab = (sender: Sender): number | null => {
    const url = sender.url?.split(/[?#]/)[0];
    const tabID = sender.tab?.id;
    if (sender.id !== browser.extensionID || url !== browser.promptURL) return null;
    return sender.origin === `chrome-extension://${browser.extensionID}` && tabID !== undefined
      ? tabID
      : null;
  };

  const live = async (tabID: number): Promise<Pending | null> => {
    const pending = await browser.session.get(pendingKey(tabID));
    if (pending === undefined) return null;
    if (pending.until > browser.now()) return pending;
    await browser.session.remove(pendingKey(tabID));
    return null;
  };

  const check = async (tabID: number, site: string, username: string, password: string) => {
    const reply = await native({
      type: "save.check",
      site,
      username,
      ...(await saltedDigest(password)),
    });
    // Same password: nothing to offer. No answer at all: nowhere to save to.
    if (reply.result === "same" || reply.error === "app_not_running") return;
    if (reply.error !== undefined && reply.error !== "busy") return;
    const action = reply.result === "differs" ? "update" : "save";
    const until = browser.now() + LIFETIME_MS;
    await browser.session.set(pendingKey(tabID), { site, username, password, action, until });
    browser.scheduleSweep();
  };

  const submitted = async (message: PageMessage, sender: Sender): Promise<boolean> => {
    const page = pageTab(sender);
    if (page === null || message.type !== "submitted") return false;
    const { username, password } = message;
    if (typeof username !== "string" || typeof password !== "string") return false;
    if (username === "" || password === "") return false;
    if (username.length > MAX_FIELD || password.length > MAX_FIELD) return false;
    await browser.session.remove(pendingKey(page.tabID));
    const work = check(page.tabID, page.site, username, password);
    checks.set(page.tabID, work);
    await work;
    checks.delete(page.tabID);
    return (await live(page.tabID)) !== null;
  };

  const view = (pending: Pending, note?: string): PromptView => ({
    host: new URL(pending.site).host,
    username: pending.username,
    action: pending.action,
    ...(note === undefined ? {} : { note }),
  });

  const finish = async (tabID: number): Promise<null> => {
    await browser.session.remove(pendingKey(tabID));
    browser.closePrompt(tabID);
    return null;
  };

  const answer = async (accept: boolean, tabID: number): Promise<PromptView | null> => {
    const pending = await live(tabID);
    if (pending === null || !accept) return finish(tabID);
    const { site, username, password } = pending;
    const replace = pending.action === "update";
    const reply = await native({ type: "save", site, username, password, replace });
    if (reply.result === "saved" || reply.result === "unchanged") return finish(tabID);
    if (reply.result === "exists") {
      const update = { ...pending, action: "update" as const };
      await browser.session.set(pendingKey(tabID), update);
      return view(update, `Bisel has another password for ${username}.`);
    }
    const retry = ["denied", "timeout", "locked", "busy"].includes(reply.error ?? "");
    if (retry) return view(pending, "Not saved.");
    return finish(tabID);
  };

  return {
    async onPageMessage(message: PageMessage, sender: Sender): Promise<boolean> {
      if (message.type === "submitted") return submitted(message, sender);
      const page = pageTab(sender);
      if (page === null) return false;
      await checks.get(page.tabID);
      return (await live(page.tabID)) !== null;
    },

    async onPromptMessage(message: PromptMessage, sender: Sender): Promise<PromptView | null> {
      const tabID = promptTab(sender);
      if (tabID === null) return null;
      if (message.type === "answer") return answer(message.accept === true, tabID);
      const pending = await live(tabID);
      return pending === null ? null : view(pending);
    },

    isFromPrompt: (sender: Sender): boolean => promptTab(sender) !== null,

    async tabClosed(tabID: number): Promise<void> {
      await browser.session.remove(pendingKey(tabID));
    },

    /** A password nobody answered for leaves memory when its time is up, whether or not anything else happens. */
    async sweep(): Promise<void> {
      for (const key of await browser.session.keys()) {
        const pending = await browser.session.get(key);
        if (pending !== undefined && pending.until <= browser.now()) {
          await browser.session.remove(key);
        }
      }
    },
  };
}
