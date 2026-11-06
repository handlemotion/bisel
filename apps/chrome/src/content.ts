import { loginFrom } from "./form";
import type { PageMessage } from "./worker";

// Runs in the top frame of https pages only, in Chrome's isolated world. It does not name the site: the worker takes that from Chrome.

let prompt: HTMLIFrameElement | null = null;

function showPrompt(): void {
  if (prompt !== null) return;
  prompt = document.createElement("iframe");
  prompt.src = chrome.runtime.getURL("prompt.html");
  prompt.title = "Bisel";
  prompt.style.cssText =
    "position:fixed;top:12px;right:12px;width:300px;height:104px;border:1px solid #8888;border-radius:8px;z-index:2147483647;color-scheme:normal";
  document.documentElement.append(prompt);
}

async function ask(message: PageMessage): Promise<void> {
  const answer: unknown = await chrome.runtime.sendMessage(message);
  if (answer === true) showPrompt();
}

document.addEventListener(
  "submit",
  (event) => {
    if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
    const login = loginFrom(event.target);
    if (login !== null) void ask({ type: "submitted", ...login });
  },
  true,
);

chrome.runtime.onMessage.addListener((message: { type?: string }) => {
  if (message.type !== "close") return;
  prompt?.remove();
  prompt = null;
});

// Most sign-ins navigate away: the next page shows what the last one left.
void ask({ type: "pending" });
