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
    this.dataset.operationEndpoint = "/v/example/upload/operations";
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

const auditWarningText = "The file was uploaded, but the durability of its storage or audit record is uncertain. Do not retry; check the result manually.";
const responseWarningText = "The server response was incomplete. The file may already have been uploaded. Do not retry; check the result manually.";
const storageWarningText = "The file was uploaded, but the durability of its storage is uncertain. Do not retry; check the result manually.";
const auditOnlyWarningText = "The file was uploaded, but the durability of its audit record is uncertain. Do not retry; check the result manually.";
const directoryWarningText = "The upload folder may have been created only partially. The file was not uploaded. Check the result manually.";
const directoryAuditWarningText = "The upload folder may have been created only partially, and its audit record is uncertain. The file was not uploaded. Check the result manually.";
assert.match(auditWarningText, /storage or audit record/);
const source = readFileSync("assets/web/upload-queue.js", "utf8");

async function runScenario(name, status, json, expectedMessage, statusResult = null) {
  const form = new Form();
  const input = new Input();
  const list = new Element();
  const submit = new Button();
  const auditWarning = new Element("span");
  auditWarning.textContent = auditWarningText;
  const storageWarning = new Element("span");
  storageWarning.textContent = storageWarningText;
  const auditOnlyWarning = new Element("span");
  auditOnlyWarning.textContent = auditOnlyWarningText;
  const directoryWarning = new Element("span");
  directoryWarning.textContent = directoryWarningText;
  const directoryAuditWarning = new Element("span");
  directoryAuditWarning.textContent = directoryAuditWarningText;
  const responseWarning = new Element("span");
  responseWarning.textContent = responseWarningText;
  form.elementsBySelector.set("[data-upload-input]", input);
  form.elementsBySelector.set("[data-upload-list]", list);
  form.elementsBySelector.set("[data-upload-submit]", submit);
  form.elementsBySelector.set("[data-upload-audit-warning]", auditWarning);
  form.elementsBySelector.set("[data-upload-storage-warning]", storageWarning);
  form.elementsBySelector.set("[data-upload-audit-only-warning]", auditOnlyWarning);
  form.elementsBySelector.set("[data-upload-directory-warning]", directoryWarning);
  form.elementsBySelector.set("[data-upload-directory-audit-warning]", directoryAuditWarning);
  form.elementsBySelector.set("[data-upload-response-warning]", responseWarning);

  const document = {
    readyState: "complete",
    documentElement: { lang: "en" },
    querySelectorAll: (selector) => selector === "form[data-upload-queue]" ? [form] : [],
    createElement: (tag) => tag === "button" ? new Button() : new Element(tag),
    createDocumentFragment: () => new Element("fragment")
  };
  let requestCount = 0;
  const fetch = async (url, options) => {
    requestCount += 1;
    if (url === form.dataset.operationEndpoint) {
      assert.equal(options.method, "POST", name);
      return { ok: true, status: 201, json: async () => ({
        upload_id: "a".repeat(43), status_url: `${url}/${"a".repeat(43)}`
      }) };
    }
    if (url.startsWith(`${form.dataset.operationEndpoint}/`)) {
      assert.equal(options.method, "GET", name);
      return { ok: true, status: 200, json: async () => ({ state: "completed", result: statusResult }) };
    }
    assert.equal(options.headers["Idempotency-Key"], "a".repeat(43), name);
    if (json === null) throw new TypeError("Upload response lost");
    return { ok: true, status, json };
  };

  runInNewContext(source, {
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

  assert.equal(requestCount, statusResult ? 3 : 2, name);
  assert.equal(form.attributes.get("aria-busy"), "false", name);
  assert.equal(list.children.length, 1, name);
  assert.equal(list.children[0].dataset.state, "warning", name);
  assert.ok(list.children[0].children[0].children[1].textContent.includes(expectedMessage), name);
  assert.equal(list.after.textContent, expectedMessage, name);
  assert.doesNotMatch(list.after.textContent, /vl-i18n|recovery will finish|upload\.successful/, name);
  assert.equal(list.children[0].children[1].children.length, 1, `${name}: warning must not offer retry`);

  form.dispatch("submit", { preventDefault() {} });
  assert.equal(requestCount, statusResult ? 3 : 2, `${name}: warning must never be uploaded again automatically`);
}

await runScenario("valid audit warning", 202, async () => ({
  file: "empty.txt", outcome: "created", warning: "audit_durability_uncertain", warnings: ["audit_durability_uncertain"]
}), auditOnlyWarningText);
await runScenario("storage warning at 200", 200, async () => ({
  file: "empty.txt", outcome: "created_uncertain", warning: "audit_durability_uncertain", warnings: ["storage_durability_uncertain"]
}), storageWarningText);
await runScenario("audit warning at 202", 202, async () => ({
  file: "empty.txt", outcome: "created", warning: "audit_durability_uncertain", warnings: ["audit_durability_uncertain"]
}), auditOnlyWarningText);
await runScenario("combined warning", 202, async () => ({
  file: "empty.txt", outcome: "created_uncertain", warning: "audit_durability_uncertain", warnings: ["storage_durability_uncertain", "audit_durability_uncertain"]
}), auditWarningText);
await runScenario("partial directory", 202, async () => ({
  file: "empty.txt", outcome: "directory_uncertain", warning: "audit_durability_uncertain", warnings: ["storage_durability_uncertain"]
}), directoryWarningText);
await runScenario("partial directory with uncertain audit", 202, async () => ({
  file: "empty.txt", outcome: "directory_uncertain", warning: "audit_durability_uncertain", warnings: ["storage_durability_uncertain", "audit_durability_uncertain"]
}), directoryAuditWarningText);
const storedAudit = { file: "empty.txt", outcome: "created", warning: "audit_durability_uncertain", warnings: ["audit_durability_uncertain"] };
await runScenario("lost response", 200, null, auditOnlyWarningText, storedAudit);
await runScenario("malformed success JSON at 200", 200, async () => { throw new SyntaxError("Invalid JSON"); }, auditOnlyWarningText, storedAudit);
await runScenario("truncated JSON", 202, async () => { throw new SyntaxError("Unexpected end of JSON input"); }, auditOnlyWarningText, storedAudit);
await runScenario("incomplete JSON object", 202, async () => ({ file: "empty.txt" }), auditOnlyWarningText, storedAudit);
await runScenario("error envelope with accepted status", 202, async () => ({ error: { code: "unknown" } }), auditOnlyWarningText, storedAudit);
await runScenario("contradictory warning fields", 200, async () => ({
  file: "empty.txt", outcome: "created", warning: "audit_durability_uncertain", warnings: []
}), auditOnlyWarningText, storedAudit);
console.log("Upload queue issues one ID per file and resolves uncertain responses via status");
