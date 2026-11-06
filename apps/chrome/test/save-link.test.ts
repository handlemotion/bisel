// @vitest-environment happy-dom
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loginFrom } from "../src/form";
import { type Browser, HOST_NAME, createWorker } from "../src/worker";

const ID = "hchnaceebnafpeijdmglkmfccfmlcelj";
const PROMPT_URL = `chrome-extension://${ID}/prompt.html`;
const PASSWORD = "correct-horse-battery";

const page = {
  id: ID,
  tab: { id: 7 },
  frameId: 0,
  origin: "https://github.com",
  url: "https://github.com/login",
} as chrome.runtime.MessageSender;
const prompt = {
  id: ID,
  tab: { id: 7 },
  frameId: 3,
  origin: `chrome-extension://${ID}`,
  url: PROMPT_URL,
} as chrome.runtime.MessageSender;

function rig(replies: Record<string, object>) {
  const sent: Array<Record<string, unknown>> = [];
  const session = new Map<string, never>();
  let now = 1000;
  const browser: Browser = {
    extensionID: ID,
    promptURL: PROMPT_URL,
    sendNative: async (message) => {
      sent.push(message as Record<string, unknown>);
      return replies[(message as { type: string }).type] ?? {};
    },
    closePrompt: () => {},
    session: {
      get: async (key) => session.get(key),
      set: async (key, value) => void session.set(key, value as never),
      remove: async (key) => void session.delete(key),
      keys: async () => [...session.keys()],
    },
    scheduleSweep: () => {},
    now: () => now,
  };
  return { worker: createWorker(browser), sent, session, pass: (ms: number) => (now += ms) };
}

const submit = { type: "submitted", username: "someone", password: PASSWORD } as const;

describe("what reaches the native host", () => {
  it("the password stays out of it until the person accepts, and then goes to the site Chrome named", async () => {
    const { worker, sent } = rig({ "save.check": { result: "new" }, save: { result: "saved" } });
    expect(await worker.onPageMessage(submit, page)).toBe(true);
    expect(JSON.stringify(sent)).not.toContain(PASSWORD);
    expect(sent).toHaveLength(1);

    await worker.onPromptMessage({ type: "answer", accept: true }, prompt);
    expect(sent[1]).toMatchObject({
      v: 1,
      type: "save",
      site: "https://github.com",
      username: "someone",
      password: PASSWORD,
      replace: false,
    });
  });

  it("the check's digest is what the app can compare against a stored password", async () => {
    const { worker, sent } = rig({ "save.check": { result: "new" } });
    await worker.onPageMessage(submit, page);
    const salt = Buffer.from(sent[0]?.["salt"] as string, "base64");
    const digest = createHash("sha256").update(salt).update(PASSWORD).digest("base64");
    expect(sent[0]?.["digest"]).toBe(digest);
  });

  it("declining sends nothing and forgets the password", async () => {
    const { worker, sent, session } = rig({ "save.check": { result: "new" } });
    await worker.onPageMessage(submit, page);
    await worker.onPromptMessage({ type: "answer", accept: false }, prompt);
    expect(sent).toHaveLength(1);
    expect(session.size).toBe(0);
  });

  it("a password nobody answered for does not outlive its time", async () => {
    const { worker, session, pass } = rig({ "save.check": { result: "new" } });
    await worker.onPageMessage(submit, page);
    expect(session.size).toBe(1);
    pass(120_001);
    await worker.sweep();
    expect(session.size).toBe(0);
  });

  it("Update is asked for only when the app said the password differs, and a Save it refuses turns into that question", async () => {
    const differs = rig({ "save.check": { result: "differs" }, save: { result: "saved" } });
    await differs.worker.onPageMessage(submit, page);
    expect(await differs.worker.onPromptMessage({ type: "prompt" }, prompt)).toMatchObject({
      action: "update",
    });
    await differs.worker.onPromptMessage({ type: "answer", accept: true }, prompt);
    expect(differs.sent[1]).toMatchObject({ replace: true });

    const locked = rig({ "save.check": { result: "unknown" }, save: { result: "exists" } });
    await locked.worker.onPageMessage(submit, page);
    const view = await locked.worker.onPromptMessage({ type: "answer", accept: true }, prompt);
    expect(locked.sent[1]).toMatchObject({ replace: false });
    expect(view).toMatchObject({ action: "update" });
  });

  it("the same password, or no app to save to, offers nothing", async () => {
    const same = rig({ "save.check": { result: "same" } });
    expect(await same.worker.onPageMessage(submit, page)).toBe(false);
    const gone = rig({ "save.check": { error: "app_not_running" } });
    expect(await gone.worker.onPageMessage(submit, page)).toBe(false);
    expect(same.session.size + gone.session.size).toBe(0);
  });
});

describe("who the worker listens to", () => {
  it("drops a submit from a cross-origin frame, a plain http page or another extension", async () => {
    for (const sender of [
      { ...page, frameId: 2 },
      { ...page, origin: "http://github.com" },
      { ...page, origin: "null" },
      { ...page, id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      { ...page, tab: undefined },
    ] as chrome.runtime.MessageSender[]) {
      const { worker, sent, session } = rig({ "save.check": { result: "new" } });
      expect(await worker.onPageMessage(submit, sender)).toBe(false);
      expect(sent).toHaveLength(0);
      expect(session.size).toBe(0);
    }
  });

  it("files the login under the origin Chrome reports, whatever the message says", async () => {
    const { worker, sent } = rig({ "save.check": { result: "new" } });
    const forged = { ...submit, site: "https://bank.example" };
    await worker.onPageMessage(forged, page);
    expect(sent[0]?.["site"]).toBe("https://github.com");
  });

  it("takes an accept from prompt.html only, so a content script cannot approve its own save", async () => {
    const { worker, sent } = rig({ "save.check": { result: "new" }, save: { result: "saved" } });
    await worker.onPageMessage(submit, page);
    const answer = { type: "answer", accept: true } as const;
    expect(worker.isFromPrompt(page)).toBe(false);
    expect(await worker.onPromptMessage(answer, page)).toBeNull();
    expect(await worker.onPageMessage(answer as never, page)).toBe(true);
    expect(sent).toHaveLength(1);
  });
});

describe("what the content script reads", () => {
  const form = (html: string): HTMLFormElement => {
    document.body.innerHTML = html;
    return document.querySelector("form") as HTMLFormElement;
  };
  const fill = (value: string) => `value="${value}"`;

  it("takes the login from the submitted form and never from anywhere else on the page", () => {
    const login = form(`
      <input type="email" autocomplete="username" ${fill("outside@example.com")}>
      <input type="password" ${fill("outside-secret")}>
      <form><input type="text" ${fill("someone")}><input type="password" ${fill(PASSWORD)}></form>`);
    expect(loginFrom(login)).toEqual({ username: "someone", password: PASSWORD });
    const alone = form(`
      <input type="text" ${fill("outside@example.com")}>
      <form><input type="password" ${fill(PASSWORD)}></form>`);
    expect(loginFrom(alone)).toBeNull();
  });

  it("leaves sign-ups, password changes and one-time codes alone", () => {
    const user = `<input type="text" ${fill("someone")}>`;
    const pw = `<input type="password" ${fill(PASSWORD)}>`;
    expect(loginFrom(form(`<form>${user}${pw}${pw}</form>`))).toBeNull();
    const fresh = `<input type="password" autocomplete="new-password" ${fill(PASSWORD)}>`;
    expect(loginFrom(form(`<form>${user}${fresh}</form>`))).toBeNull();
    const code = `<input type="password" autocomplete="one-time-code" ${fill("123456")}>`;
    expect(loginFrom(form(`<form>${user}${code}</form>`))).toBeNull();
  });
});

describe("the fixed link", () => {
  it("the extension's key gives the ID, and the ID and host name are the ones the app pins", () => {
    const manifest = JSON.parse(readFileSync("public/manifest.json", "utf8"));
    const derived = createHash("sha256")
      .update(Buffer.from(manifest.key, "base64"))
      .digest("hex")
      .slice(0, 32)
      .replace(/[0-9a-f]/g, (c: string) => String.fromCharCode(97 + Number.parseInt(c, 16)));
    expect(derived).toBe(ID);
    const wire = readFileSync(
      "../mac/Packages/BiselCore/Sources/BiselAgent/BrowserWire.swift",
      "utf8",
    );
    expect(wire).toContain(`extensionID = "${ID}"`);
    expect(wire).toContain(`hostName = "${HOST_NAME}"`);
  });

  it("asks for no more than it needs: no fill, no cross-origin frames, no private windows", () => {
    const manifest = JSON.parse(readFileSync("public/manifest.json", "utf8"));
    expect(manifest.permissions.sort()).toEqual(["alarms", "nativeMessaging", "storage"]);
    expect(manifest.incognito).toBe("not_allowed");
    expect(manifest.content_scripts[0].all_frames).toBe(false);
    expect(manifest.content_scripts[0].matches).toEqual(["https://*/*"]);
  });
});
