
(() => {
  "use strict";

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes < 1) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / (1024 ** unit);
    return `${value.toLocaleString(document.documentElement.lang || "en", { maximumFractionDigits: unit === 0 ? 0 : 1 })} ${units[unit]}`;
  };

  const outcomeText = (outcome) => {
    switch (outcome) {
      case "created": return '<vl-i18n key="upload.uploaded"/>';
      case "replaced": return '<vl-i18n key="upload.replaced"/>';
      case "created_uncertain": return '<vl-i18n key="upload.persist_pending"/>';
      case "replaced_uncertain": return '<vl-i18n key="upload.replace_pending"/>';
      default: return '<vl-i18n key="upload.uploaded"/>';
    }
  };

  const initialize = (form, formIndex) => {
    if (!(form instanceof HTMLFormElement) || form.dataset.uploadQueueReady === "true") return;

    const input = form.querySelector("[data-upload-input]");
    const folderInput = form.querySelector("[data-upload-folder-input]");
    const list = form.querySelector("[data-upload-list]");
    const dropzone = form.querySelector("[data-upload-dropzone]");
    const submit = form.querySelector("[data-upload-submit]");
    const endpoint = form.dataset.queueEndpoint;
    const operationEndpoint = form.dataset.operationEndpoint;
    const auditWarningText = form.querySelector("[data-upload-audit-warning]")?.textContent?.trim() ||
      "The file was uploaded, but the durability of its storage or audit record is uncertain. Do not retry; check the result manually.";
    const storageWarningText = form.querySelector("[data-upload-storage-warning]")?.textContent?.trim() ||
      "The file was uploaded, but the durability of its storage is uncertain. Do not retry; check the result manually.";
    const auditOnlyWarningText = form.querySelector("[data-upload-audit-only-warning]")?.textContent?.trim() ||
      "The file was uploaded, but the durability of its audit record is uncertain. Do not retry; check the result manually.";
    const directoryWarningText = form.querySelector("[data-upload-directory-warning]")?.textContent?.trim() ||
      "The upload folder may have been created only partially. The file was not uploaded. Check the result manually.";
    const directoryAuditWarningText = form.querySelector("[data-upload-directory-audit-warning]")?.textContent?.trim() ||
      "The upload folder may have been created only partially, and its audit record is uncertain. The file was not uploaded. Check the result manually.";
    const responseWarningText = form.querySelector("[data-upload-response-warning]")?.textContent?.trim() ||
      "The server response was incomplete. The file may already have been uploaded. Do not retry; check the result manually.";
    if (!(input instanceof HTMLInputElement) || input.type !== "file" || !input.name ||
        !(list instanceof HTMLElement) || !endpoint || !operationEndpoint) return;
    if (input.disabled) return;

    const feedback = document.createElement("p");
    feedback.className = "vl-muted";
    feedback.dataset.uploadFeedback = "";
    feedback.id = `vl-upload-feedback-${formIndex}`;
    feedback.setAttribute("role", "status");
    feedback.setAttribute("aria-live", "polite");
    list.insertAdjacentElement("afterend", feedback);
    input.setAttribute("aria-describedby", feedback.id);

    let sequence = 0;
    let running = false;
    let dragDepth = 0;
    const items = [];

    const setFeedback = (message) => {
      feedback.textContent = message;
    };

    const setBusy = (busy) => {
      running = busy;
      form.setAttribute("aria-busy", busy ? "true" : "false");
      if (submit instanceof HTMLButtonElement || submit instanceof HTMLInputElement) {
        submit.disabled = busy;
      }
    };

    const removeItem = (item) => {
      if (running || item.status === "uploading") return;
      const index = items.indexOf(item);
      if (index !== -1) items.splice(index, 1);
      render();
      setFeedback(items.length === 0 ? '<vl-i18n key="upload.none_selected"/>' : '<vl-i18n key="upload.removed_queue"/>');
    };

    const retryItem = async (item) => {
      if (running || !["ready", "retryable"].includes(item.status)) return;
      item.status = "ready";
      item.message = '<vl-i18n key="upload.ready"/>';
      render();
      await processItems([item]);
    };

    const actionButton = (label, action, disabled = false) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "vl-button vl-button--ghost";
      button.textContent = label;
      button.disabled = disabled;
      button.addEventListener("click", action);
      return button;
    };

    const render = () => {
      const fragment = document.createDocumentFragment();
      for (const item of items) {
        const row = document.createElement("div");
        row.className = "vl-upload-item";
        row.dataset.state = item.status;

        const description = document.createElement("div");
        description.className = "vl-stack vl-stack--compact";
        const name = document.createElement("strong");
        name.textContent = item.relativePath || item.serverFile || item.file.name;
        const meta = document.createElement("span");
        meta.className = "vl-muted";
        meta.textContent = `${formatBytes(item.file.size)} · ${item.message}`;
        description.append(name, meta);

        const actions = document.createElement("div");
        actions.className = "vl-inline";
        if (item.status === "error") {
          if (!item.uploadId) {
            actions.append(actionButton('<vl-i18n key="upload.retry"/>', () => { item.status = "ready"; void retryItem(item); }, running));
          }
        }
        if (item.status === "retryable") {
          actions.append(actionButton('<vl-i18n key="upload.retry"/>', () => { void retryItem(item); }, running));
        }
        if (item.status === "checking") {
          actions.append(actionButton('<vl-i18n key="upload.check_status"/>', () => { void checkItemStatus(item); }, running));
        }
        actions.append(actionButton(
          item.status === "success" || item.status === "warning"
            ? '<vl-i18n key="upload.remove_list"/>' : '<vl-i18n key="common.remove"/>',
          () => removeItem(item),
          running || item.status === "uploading"
        ));

        row.append(description, actions);
        fragment.append(row);
      }
      list.replaceChildren(fragment);
    };

    const addFiles = (fileList) => {
      const files = Array.from(fileList || []).filter((file) => file instanceof File);
      for (const file of files) {
        const relativePath = typeof file.webkitRelativePath === "string"
          ? file.webkitRelativePath.replace(/\\/g, "/").replace(/^\/+/, "")
          : "";
        const components = relativePath.split("/").filter(Boolean);
        const relativeDirectory = components.length > 1 ? components.slice(0, -1).join("/") : "";
        items.push({
          id: ++sequence,
          file,
          relativePath,
          relativeDirectory,
          status: "ready",
          message: '<vl-i18n key="upload.ready"/>',
          serverFile: "",
          outcome: "",
          uploadId: "",
          statusUrl: "",
          uploadData: null
        });
      }
      render();
      if (files.length > 0) {
        setFeedback(`${files.length} ${files.length === 1 ? '<vl-i18n key="upload.file_added"/>' : '<vl-i18n key="upload.files_added"/>'}`);
      }
    };

    const requestData = (item) => {
      const data = new FormData(form);
      data.delete("upload_id");
      for (const fileInput of form.querySelectorAll('input[type="file"][name]')) {
        data.delete(fileInput.name);
      }
      if (item.relativeDirectory) data.append("folder_path", item.relativeDirectory);
      data.append(input.name, item.file, item.file.name);
      return data;
    };

    const csrfHeader = () => {
      const csrf = form.querySelector('input[name="csrf"]')?.value || "";
      return endpoint.startsWith("/admin/")
        ? { "X-CSRF-Token": csrf }
        : { "X-VaultLink-Upload-CSRF": csrf };
    };

    const ensureOperation = async (item) => {
      if (item.uploadId) return;
      item.uploadData = requestData(item);
      const response = await fetch(operationEndpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Accept": "application/json", ...csrfHeader() }
      });
      if (response.status !== 201) throw new Error(`<vl-i18n key="upload.failed"/> (${response.status})`);
      const ticket = await response.json();
      if (!ticket || typeof ticket.upload_id !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(ticket.upload_id) ||
          typeof ticket.status_url !== "string" ||
          !ticket.status_url.startsWith(`${operationEndpoint}/`)) {
        throw new Error('<vl-i18n key="upload.invalid_response"/>');
      }
      item.uploadId = ticket.upload_id;
      item.statusUrl = ticket.status_url;
    };

    const showResult = (item, payload) => {
      if (!payload || payload.file !== item.file.name ||
          !["created", "replaced", "created_uncertain", "replaced_uncertain", "directory_uncertain"].includes(payload.outcome) ||
          (payload.warnings !== undefined && (!Array.isArray(payload.warnings) ||
            payload.warnings.some((warning) => !["storage_durability_uncertain", "audit_durability_uncertain"].includes(warning))))) {
        return false;
      }
      const causes = Array.isArray(payload.warnings) ? payload.warnings : [];
      const storageUncertain = causes.includes("storage_durability_uncertain");
      const auditUncertain = causes.includes("audit_durability_uncertain");
      if (causes.length !== new Set(causes).size ||
          causes.join(",") !== ["storage_durability_uncertain", "audit_durability_uncertain"]
            .filter((cause) => causes.includes(cause)).join(",") ||
          (["created_uncertain", "replaced_uncertain", "directory_uncertain"].includes(payload.outcome) !== storageUncertain) ||
          (payload.warning != null && payload.warning !== "audit_durability_uncertain") ||
          (payload.warning === "audit_durability_uncertain") !== (causes.length > 0)) {
        return false;
      }
      const warning = causes.length > 0;
      item.status = warning ? "warning" : "success";
      item.serverFile = payload.file;
      item.outcome = payload.outcome;
      item.message = payload.outcome === "directory_uncertain"
        ? auditUncertain ? directoryAuditWarningText : directoryWarningText
        : storageUncertain && auditUncertain ? auditWarningText
        : storageUncertain ? storageWarningText
        : auditUncertain ? auditOnlyWarningText
        : payload.warning === "audit_durability_uncertain" ? auditWarningText
        : warning ? responseWarningText : outcomeText(payload.outcome);
      return true;
    };

    const checkItemStatus = async (item) => {
      if (!item.statusUrl) return;
      item.status = "uploading";
      item.message = '<vl-i18n key="upload.checking_status"/>';
      render();
      try {
        const response = await fetch(item.statusUrl, {
          method: "GET", credentials: "same-origin", headers: { "Accept": "application/json" }
        });
        if (response.status === 410) {
          item.status = "expired";
          item.message = '<vl-i18n key="upload.id_expired"/>';
          return;
        }
        if (!response.ok) throw new Error("Status unavailable");
        const receipt = await response.json();
        switch (receipt?.state) {
          case "completed":
            if (!showResult(item, receipt.result)) throw new Error("Invalid stored result");
            break;
          case "ready":
          case "retryable":
            item.status = "retryable";
            item.message = '<vl-i18n key="upload.retry"/>';
            break;
          case "outcome_unknown":
            item.status = "unknown";
            item.message = '<vl-i18n key="upload.outcome_unknown"/>';
            break;
          case "rejected":
            item.status = "rejected";
            item.message = '<vl-i18n key="upload.failed"/>';
            break;
          case "processing":
            item.status = "checking";
            item.message = '<vl-i18n key="upload.in_progress"/>';
            break;
          default:
            throw new Error("Unknown upload state");
        }
      } catch (_) {
        item.status = "checking";
        item.message = responseWarningText;
      } finally {
        render();
      }
    };

    const uploadItem = async (item) => {
      item.status = "uploading";
      item.message = '<vl-i18n key="upload.uploading"/>';
      render();

      try {
        await ensureOperation(item);
        const response = await fetch(endpoint, {
          method: "POST",
          body: item.uploadData,
          credentials: "same-origin",
          headers: { "Accept": "application/json", "Idempotency-Key": item.uploadId }
        });

        let payload;
        try {
          payload = await response.json();
        } catch (_) {
          await checkItemStatus(item);
          return;
        }

        if (response.status === 409 || response.status === 410 || response.ok && payload?.error) {
          await checkItemStatus(item);
          return;
        }

        if (!response.ok || (payload && payload.error)) {
          const error = payload && payload.error;
          const message = error && typeof error.message === "string"
            ? error.message
            : `<vl-i18n key="upload.failed"/> (${response.status})`;
          const code = error && typeof error.code === "string" ? ` [${error.code}]` : "";
          throw new Error(`${message}${code}`);
        }
        if (!showResult(item, payload) || response.status === 202 && item.status !== "warning") {
          await checkItemStatus(item);
          return;
        }
      } catch (error) {
        if (item.uploadId) {
          await checkItemStatus(item);
          return;
        }
        item.status = "error";
        item.message = error instanceof Error ? error.message : '<vl-i18n key="upload.failed"/>';
      }
      render();
    };

    async function processItems(queue) {
      if (running || queue.length === 0) return;
      setBusy(true);
      render();
      for (const item of queue) {
        if (item.status === "ready") {
          await uploadItem(item);
        }
      }
      setBusy(false);
      render();

      const successful = queue.filter((item) => item.status === "success").length;
      const warned = queue.filter((item) => item.status === "warning");
      const failed = queue.filter((item) => ["error", "retryable", "checking", "rejected", "expired", "unknown"].includes(item.status)).length;
      const result = [];
      if (successful > 0) result.push(`${successful} <vl-i18n key="upload.successful"/>`);
      if (warned.length > 0) result.push(...new Set(warned.map((item) => item.message)));
      if (failed > 0) result.push(`${failed} <vl-i18n key="upload.failed_retry"/>`);
      setFeedback(result.join(", "));
    }

    input.addEventListener("change", () => {
      addFiles(input.files);
      input.value = "";
    });
    if (folderInput instanceof HTMLInputElement) {
      if (!("webkitdirectory" in folderInput)) {
        folderInput.closest("label")?.setAttribute("hidden", "");
      } else {
        folderInput.addEventListener("change", () => {
          addFiles(folderInput.files);
          folderInput.value = "";
        });
      }
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (running) return;
      const queue = items.filter((item) => item.status === "ready");
      if (queue.length === 0) {
        setFeedback(items.some((item) => item.status === "warning")
          ? items.find((item) => item.status === "warning").message
          : items.some((item) => item.status === "success")
          ? '<vl-i18n key="upload.already_done"/>'
          : '<vl-i18n key="upload.select_one"/>');
        input.focus();
        return;
      }
      void processItems(queue);
    });

    if (dropzone instanceof HTMLElement) {
      const stopDrag = (event) => {
        event.preventDefault();
        event.stopPropagation();
      };
      dropzone.addEventListener("dragenter", (event) => {
        stopDrag(event);
        dragDepth += 1;
        dropzone.dataset.dragging = "true";
      });
      dropzone.addEventListener("dragover", stopDrag);
      dropzone.addEventListener("dragleave", (event) => {
        stopDrag(event);
        dragDepth = Math.max(0, dragDepth - 1);
        if (dragDepth === 0) delete dropzone.dataset.dragging;
      });
      dropzone.addEventListener("drop", (event) => {
        stopDrag(event);
        dragDepth = 0;
        delete dropzone.dataset.dragging;
        if (event.dataTransfer) addFiles(event.dataTransfer.files);
      });
    }

    // Keep the SSR form a true single-file fallback until initialization is complete.
    input.required = false;
    input.multiple = true;
    form.dataset.uploadQueueReady = "true";
    setFeedback('<vl-i18n key="upload.none_selected"/>');
  };

  const initializeAll = () => {
    document.querySelectorAll("form[data-upload-queue]").forEach((form, index) => {
      try {
        initialize(form, index);
      } catch (error) {
        // A broken enhancement must never disable the server-rendered fallback.
        console.error("VaultLink upload queue could not be initialized", error);
      }
    });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeAll, { once: true });
  } else {
    initializeAll();
  }
})();
