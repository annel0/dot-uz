// DotURL transport v2: chat-safe Base64URL; legacy Base81 decode retained.
import { DotURL, redirectFromHash } from "./doturl-browser.js";

const PUBLIC_ORIGIN = "https://⏺.uz";

const site = document.getElementById("site");
const dot = document.getElementById("dot");
const menuPanel = document.getElementById("menuPanel");
const formPanel = document.getElementById("formPanel");
const resultPanel = document.getElementById("resultPanel");
const shortenButton = document.getElementById("shortenButton");
const shortenForm = document.getElementById("shortenForm");
const urlInput = document.getElementById("urlInput");
const submitButton = document.getElementById("submitButton");
const errorText = document.getElementById("errorText");
const resultLink = document.getElementById("resultLink");
const copyButton = document.getElementById("copyButton");

const panels = [menuPanel, formPanel, resultPanel];
let state = "closed";
let resultURL = "";

function setPanel(panel) {
  for (const item of panels) {
    const active = item === panel;
    item.classList.toggle("active", active);
    item.setAttribute("aria-hidden", active ? "false" : "true");
  }
}

function setState(next) {
  state = next;
  const open = next !== "closed";
  site.classList.toggle("open", open);
  dot.setAttribute("aria-expanded", open ? "true" : "false");
  dot.setAttribute("aria-label", open ? "Закрыть меню" : "Открыть меню");

  if (next === "closed") {
    setPanel(null);
    errorText.textContent = "";
    return;
  }

  if (next === "menu") {
    setPanel(menuPanel);
    return;
  }

  if (next === "form") {
    setPanel(formPanel);
    requestAnimationFrame(() => urlInput.focus());
    return;
  }

  if (next === "result") {
    setPanel(resultPanel);
  }
}

function normalizeURL(value) {
  let input = value.trim();
  if (!input) throw new Error("вставь ссылку");

  if (!/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(input)) {
    input = `https://${input}`;
  }

  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error("не похоже на ссылку");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("только http или https");
  }

  return input;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const ok = document.execCommand("copy");
  textarea.remove();
  if (!ok) throw new Error("copy failed");
}

async function showResult(target) {
  submitButton.disabled = true;
  errorText.textContent = "";

  try {
    const encoded = DotURL.encode(target, { safe: false });
    resultURL = `${PUBLIC_ORIGIN}/#${encoded.fragment}`;

    resultLink.href = resultURL;
    resultLink.textContent = resultURL;
    copyButton.textContent = "скопировать";
    setState("result");

    try {
      await copyText(resultURL);
      copyButton.textContent = "скопировано";
    } catch {
      // Clipboard may be blocked outside HTTPS or without user permission.
    }
  } finally {
    submitButton.disabled = false;
  }
}

// A valid DotURL hash wins over the landing UI.
// Only http(s) targets are allowed by redirectFromHash().
const redirecting = redirectFromHash({ safeOnly: false, replace: true });
if (!redirecting) {
  document.documentElement.classList.remove("booting");
}

// Hard fallback so an unexpected runtime error never leaves a blank page.
setTimeout(() => document.documentElement.classList.remove("booting"), 1200);

dot.addEventListener("click", (event) => {
  if (event.target.closest("button, input, a, form")) return;

  if (state === "closed") setState("menu");
  else if (state === "menu") setState("closed");
});

dot.addEventListener("keydown", (event) => {
  if (event.target !== dot) return;
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    setState(state === "closed" ? "menu" : "closed");
  }
});

shortenButton.addEventListener("click", () => {
  setState("form");
});

shortenForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    const target = normalizeURL(urlInput.value);
    await showResult(target);
  } catch (error) {
    errorText.textContent = error?.message || "не удалось сжать";
    urlInput.focus();
  }
});

copyButton.addEventListener("click", async () => {
  if (!resultURL) return;

  try {
    await copyText(resultURL);
    copyButton.textContent = "скопировано";
  } catch {
    copyButton.textContent = "не скопировалось";
  }
});

resultLink.addEventListener("click", (event) => {
  // Normal link behavior. No menu toggling.
  event.stopPropagation();
});

document.addEventListener("pointerdown", (event) => {
  if (state !== "closed" && !site.contains(event.target)) {
    setState("closed");
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;

  if (state === "result") {
    setState("form");
    return;
  }

  if (state === "form") {
    setState("menu");
    return;
  }

  if (state === "menu") {
    setState("closed");
    dot.focus();
  }
});
