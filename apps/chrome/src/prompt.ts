import type { PromptMessage, PromptView } from "./worker";

// An extension page in an iframe: the page around it cannot read it, and only this page can accept.

const element = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;
const send = (message: PromptMessage): Promise<PromptView | null> =>
  chrome.runtime.sendMessage(message);

function show(view: PromptView): void {
  const update = view.action === "update";
  element("title").textContent = update ? "Update in Bisel?" : "Save to Bisel?";
  element("detail").textContent = view.note ?? `${view.username} on ${view.host}`;
  element("accept").textContent = update ? "Update" : "Save";
}

element("accept").addEventListener("click", async (event) => {
  if (!event.isTrusted) return;
  const button = event.currentTarget as HTMLButtonElement;
  button.disabled = true;
  element("detail").textContent = "Confirm with Touch ID.";
  const view = await send({ type: "answer", accept: true });
  button.disabled = false;
  if (view !== null) show(view);
});

element("decline").addEventListener("click", () => void send({ type: "answer", accept: false }));

void send({ type: "prompt" }).then((view) => {
  if (view !== null) show(view);
});
