import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

class Element {
  constructor(tagName = "div") {
    this.tagName = tagName;
    this.dataset = {};
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
    this.textContent = "";
  }

  addEventListener(name, listener) { this.listeners.set(name, listener); }
  dispatch(name, event = {}) { this.listeners.get(name)?.(event); }
  setAttribute(name, value) { this.attributes.set(name, value); }
  append(...children) { this.children.push(...children); }
  insertAdjacentElement(_position, child) { this.after = child; }
  replaceChildren(child) { this.children = child.children; }
  focus() {}
}

class Form extends Element {
  constructor() {
    super("form");
    this.dataset.uploadQueue = "";
    this.dataset.queueEndpoint = "/v/example/upload/queue";
    this.elementsBySelector = new Map();
  }

  querySelector(selector) { return this.elementsBySelector.get(selector) ?? null; }
  querySelectorAll(selector) {
    return selector === 'input[type="file"][name]'
      ? [this.elementsBySelector.get("[data-upload-input]")]
      : [];
  }
}

class Input extends Element {
  constructor() {
    super("input");
    this.type = "file";
    this.name = "file";
    this.files = [];
  }
}

class Button extends Element { constructor() { super("button"); } }
class File { constructor(name) { this.name = name; this.size = 0; } }
class FormData {
  constructor() { this.fields = new Map(); }
  delete(name) { this.fields.delete(name); }
  append(name, value) { this.fields.set(name, value); }
}

const form = new Form();
const input = new Input();
const list = new Element();
const submit = new Button();
const auditWarning = new Element("span");
auditWarning.textContent = "The file operation completed, but its audit durability is uncertain. Do not retry.";
form.elementsBySelector.set("[data-upload-input]", input);
form.elementsBySelector.set("[data-upload-list]", list);
form.elementsBySelector.set("[data-upload-submit]", submit);
form.elementsBySelector.set("[data-upload-audit-warning]", auditWarning);

const document = {
  readyState: "complete",
  documentElement: { lang: "en" },
  querySelectorAll: (selector) => selector === "form[data-upload-queue]" ? [form] : [],
  createElement: (tag) => tag === "button" ? new Button() : new Element(tag),
  createDocumentFragment: () => new Element("fragment")
};
let requestCount = 0;
const fetch = async () => {
  requestCount += 1;
  return {
    ok: true,
    status: 202,
    json: async () => ({
      file: "empty.txt",
      outcome: "created",
      warning: "audit_durability_uncertain"
    })
  };
};

runInNewContext(readFileSync("assets/web/upload-queue.js", "utf8"), {
  document, fetch, console, File, FormData,
  HTMLElement: Element, HTMLFormElement: Form,
  HTMLInputElement: Input, HTMLButtonElement: Button
});

input.files = [new File("empty.txt")];
input.dispatch("change");
form.dispatch("submit", { preventDefault() {} });
for (let attempt = 0; attempt < 20 && form.attributes.get("aria-busy") !== "false"; attempt += 1) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

assert.equal(requestCount, 1);
assert.equal(form.attributes.get("aria-busy"), "false");
assert.equal(list.children.length, 1);
assert.equal(list.children[0].dataset.state, "warning");
assert.match(list.children[0].children[0].children[1].textContent, /Do not retry/);
assert.match(list.after.textContent, /Do not retry/);
assert.doesNotMatch(list.after.textContent, /vl-i18n/);
assert.doesNotMatch(list.after.textContent, /upload\.successful/);
assert.equal(list.children[0].children[1].children.length, 1, "warning must not offer retry");

form.dispatch("submit", { preventDefault() {} });
assert.equal(requestCount, 1, "warning must never be uploaded again automatically");
console.log("Upload queue retains HTTP 202 audit warnings without retry");
