import {
  type Browser,
  HOST_NAME,
  type PageMessage,
  type PromptMessage,
  createWorker,
} from "./worker";

const SWEEP = "sweep";

// chrome.storage.session is held in memory, never on disk, and content scripts cannot read it.
const browser: Browser = {
  extensionID: chrome.runtime.id,
  promptURL: chrome.runtime.getURL("prompt.html"),
  sendNative: (message) => chrome.runtime.sendNativeMessage(HOST_NAME, message),
  closePrompt: (tabID) => {
    chrome.tabs.sendMessage(tabID, { type: "close" }, { frameId: 0 }).catch(() => {});
  },
  session: {
    get: async (key) => (await chrome.storage.session.get(key))[key] as never,
    set: (key, value) => chrome.storage.session.set({ [key]: value }),
    remove: (key) => chrome.storage.session.remove(key),
    keys: async () => Object.keys(await chrome.storage.session.get(null)),
  },
  scheduleSweep: () => void chrome.alarms.create(SWEEP, { delayInMinutes: 2.1 }),
  now: () => Date.now(),
};

const worker = createWorker(browser);

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  const work = worker.isFromPrompt(sender)
    ? worker.onPromptMessage(message as PromptMessage, sender)
    : worker.onPageMessage(message as PageMessage, sender);
  work.then(respond, () => respond(null));
  return true;
});

chrome.tabs.onRemoved.addListener((tabID) => void worker.tabClosed(tabID));
chrome.alarms.onAlarm.addListener(() => void worker.sweep());
