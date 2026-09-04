
document.addEventListener('DOMContentLoaded', () => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const bootstrapToken = fragment.get('token');
  if (bootstrapToken) {
    history.replaceState(null, '', location.pathname + location.search);
    fetch('/bootstrap', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({token: bootstrapToken})
    }).then(response => {
      if (!response.ok) throw new Error('setup bootstrap rejected');
      location.replace('/');
    }).catch(() => {});
    return;
  }
  const form = document.querySelector('[data-setup-form]');
  if (!form) return;

  const mode = form.querySelector('[data-server-mode]');
  const certificateSource = form.querySelector('[data-certificate-source]');
  const requireMount = form.querySelector('[data-require-mount]');
  const rootMountPath = form.elements.root_mount_path;
  const internalDirectory = form.elements.internal_directory;
  const internalDirectoryPicker = form.querySelector('[data-dir-picker="internal_directory"]');
  const expectedFilesystemType = form.elements.expected_filesystem_type;
  const expectedMountSource = form.elements.expected_mount_source;
  const externalWriters = form.querySelector('[data-external-writers]');
  const externalWritersField = form.querySelector('[data-external-writers-field]');
  const externalWriterReplace = form.querySelector('[data-external-writer-replace]');
  const externalWriterReplaceField = form.querySelector('[data-external-writer-replace-field]');
  const developmentInternalDirectory = () => {
    const root = rootMountPath.value.replace(/\/+$/, '');
    return root ? `${root}/.vaultlink-internal` : '/.vaultlink-internal';
  };
  let internalDirectoryIsAutomatic =
    internalDirectory.value === developmentInternalDirectory();
  const syncAutomaticInternalDirectory = () => {
    if (internalDirectoryIsAutomatic) {
      internalDirectory.value = developmentInternalDirectory();
    }
  };
  const syncConditionalFields = () => {
    const selectedMode = mode?.value || 'development';
    const selectedCertificate = certificateSource?.value || 'files';
    const production = selectedMode !== 'development';
    if (production || externalWriters?.checked) requireMount.checked = true;
    if (!requireMount.checked) {
      expectedFilesystemType.value = '';
      expectedMountSource.value = '';
      externalWriters.checked = false;
      externalWriterReplace.checked = false;
      syncAutomaticInternalDirectory();
    }
    internalDirectory.readOnly = !requireMount.checked;
    internalDirectoryPicker.hidden = !requireMount.checked;
    const cifsStorage = expectedFilesystemType.value === 'cifs';
    externalWritersField.hidden = !cifsStorage;
    if (!cifsStorage) externalWriters.checked = false;
    const externalClientsEnabled = cifsStorage && externalWriters.checked;
    externalWriterReplaceField.hidden = !externalClientsEnabled;
    if (!externalClientsEnabled) externalWriterReplace.checked = false;
    const standalone = selectedMode === 'standalone_tls';
    const mountPolicyRequired = production || requireMount?.checked || externalWriters?.checked;
    form.querySelectorAll('[data-mount-policy-field]').forEach(element => {
      element.required = mountPolicyRequired;
    });
    form.querySelectorAll('[data-production-section]').forEach(element => {
      element.hidden = selectedMode === 'development';
    });
    form.querySelectorAll('[data-mode-only]').forEach(element => {
      element.hidden = element.dataset.modeOnly !== selectedMode;
    });
    form.querySelectorAll('[data-certificate-only]').forEach(element => {
      element.hidden = !standalone || element.dataset.certificateOnly !== selectedCertificate;
    });
    for (const name of ['tls_cert_file', 'tls_key_file']) {
      const input = form.elements[name];
      if (input) input.required = standalone && selectedCertificate === 'files';
    }
    for (const name of ['letsencrypt_contact_email', 'letsencrypt_cache_dir']) {
      const input = form.elements[name];
      if (input) input.required = standalone && selectedCertificate === 'letsencrypt';
    }
  };
  mode?.addEventListener('change', syncConditionalFields);
  certificateSource?.addEventListener('change', syncConditionalFields);
  requireMount?.addEventListener('change', () => {
    if (!requireMount.checked) {
      externalWriters.checked = false;
      externalWriterReplace.checked = false;
      internalDirectoryIsAutomatic = true;
    }
    syncConditionalFields();
  });
  rootMountPath?.addEventListener('input', syncAutomaticInternalDirectory);
  internalDirectory?.addEventListener('input', () => {
    internalDirectoryIsAutomatic = false;
  });
  externalWriters?.addEventListener('change', syncConditionalFields);
  externalWriterReplace?.addEventListener('change', syncConditionalFields);
  form.addEventListener('submit', syncConditionalFields);
  syncConditionalFields();

  const detectedMountSelect = form.querySelector('[data-detected-mount]');
  const refreshMountsButton = form.querySelector('[data-refresh-mounts]');
  const detectedMountStatus = form.querySelector('[data-mount-status]');
  let detectedMounts = new Map();
  const applyDetectedMount = mount => {
    rootMountPath.value = mount.root_mount_path;
    internalDirectory.value = mount.internal_directory;
    internalDirectoryIsAutomatic = true;
    expectedFilesystemType.value = mount.expected_filesystem_type;
    expectedMountSource.value = mount.expected_mount_source;
    requireMount.checked = true;
    syncConditionalFields();
    detectedMountStatus.textContent = '<vl-i18n key="setup.cifs_mount_applied"/>';
  };
  const canAutoApplyDetectedMount = () =>
    form.elements.root_mount_path.value === '/tmp/vaultlink-root'
    && form.elements.internal_directory.value === '/tmp/vaultlink-root/.vaultlink-internal'
    && form.elements.expected_filesystem_type.value === ''
    && form.elements.expected_mount_source.value === '';
  async function refreshDetectedMounts(autoApply = false) {
    refreshMountsButton.disabled = true;
    try {
      const previousMountPoint = detectedMountSelect.value;
      const response = await fetch('/mounts');
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'mount discovery failed');
      detectedMounts = new Map(payload.mounts.map(mount => [mount.mount_point, mount]));
      detectedMountSelect.replaceChildren();
      const readyMounts = payload.mounts.filter(mount => mount.ready);
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = readyMounts.length
        ? '<vl-i18n key="setup.choose_cifs_mount"/>'
        : '<vl-i18n key="setup.no_cifs_mounts"/>';
      detectedMountSelect.appendChild(placeholder);
      for (const mount of payload.mounts) {
        const option = document.createElement('option');
        option.value = mount.mount_point;
        option.disabled = !mount.ready;
        option.textContent = `${mount.expected_mount_source} → ${mount.mount_point}${mount.ready ? '' : ' · <vl-i18n key="setup.cifs_layout_incomplete"/>'}`;
        detectedMountSelect.appendChild(option);
      }
      detectedMountSelect.disabled = readyMounts.length === 0;
      detectedMountStatus.textContent = readyMounts.length
        ? '<vl-i18n key="setup.detected_cifs_mount_help"/>'
        : '<vl-i18n key="setup.cifs_discovery_hint"/>';
      const matchingMount = readyMounts.find(mount => mount.mount_point === previousMountPoint)
        || readyMounts.find(mount =>
          mount.root_mount_path === form.elements.root_mount_path.value
          && mount.internal_directory === form.elements.internal_directory.value
          && mount.expected_filesystem_type === form.elements.expected_filesystem_type.value
          && mount.expected_mount_source === form.elements.expected_mount_source.value);
      if (matchingMount) {
        detectedMountSelect.value = matchingMount.mount_point;
      } else if (autoApply && readyMounts.length === 1 && canAutoApplyDetectedMount()) {
        detectedMountSelect.value = readyMounts[0].mount_point;
        applyDetectedMount(readyMounts[0]);
      }
    } catch (_) {
      detectedMounts = new Map();
      detectedMountSelect.disabled = true;
      detectedMountStatus.textContent = '<vl-i18n key="setup.cifs_discovery_failed"/>';
    } finally {
      refreshMountsButton.disabled = false;
    }
  }
  detectedMountSelect?.addEventListener('change', () => {
    const mount = detectedMounts.get(detectedMountSelect.value);
    if (mount?.ready) applyDetectedMount(mount);
  });
  refreshMountsButton?.addEventListener('click', () => refreshDetectedMounts(false));
  refreshDetectedMounts(true);

  const infoTriggers = [...form.querySelectorAll('.vl-field-info')];
  const positionInfoPopup = trigger => {
    const tooltip = trigger.querySelector('.vl-field-tooltip');
    if (!tooltip) return;
    const triggerRect = trigger.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const margin = 16;
    const halfWidth = tooltipRect.width / 2;
    const left = Math.max(
      margin + halfWidth,
      Math.min(window.innerWidth - margin - halfWidth, triggerRect.left + triggerRect.width / 2),
    );
    let top = triggerRect.bottom + 8;
    if (top + tooltipRect.height > window.innerHeight - margin
      && triggerRect.top - tooltipRect.height - 8 >= margin) {
      top = triggerRect.top - tooltipRect.height - 8;
    }
    tooltip.style.setProperty('--vl-tooltip-left', `${left}px`);
    tooltip.style.setProperty('--vl-tooltip-top', `${top}px`);
  };
  const closeInfoPopups = except => {
    for (const trigger of infoTriggers) {
      if (trigger === except) continue;
      trigger.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
    }
  };
  for (const trigger of infoTriggers) {
    trigger.setAttribute('aria-expanded', 'false');
    trigger.addEventListener('pointerenter', () => positionInfoPopup(trigger));
    trigger.addEventListener('focus', () => positionInfoPopup(trigger));
    trigger.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
      positionInfoPopup(trigger);
      const open = !trigger.classList.contains('is-open');
      closeInfoPopups(trigger);
      trigger.classList.toggle('is-open', open);
      trigger.setAttribute('aria-expanded', String(open));
      trigger.focus();
    });
    trigger.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        trigger.click();
      } else if (event.key === 'Escape') {
        trigger.classList.remove('is-open');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.blur();
      }
    });
    trigger.addEventListener('blur', () => {
      trigger.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
    });
  }
  document.addEventListener('click', () => closeInfoPopups());

  const dialog = document.querySelector('[data-dir-dialog]');
  if (!dialog?.showModal) return;
  const list = dialog.querySelector('[data-dir-list]');
  const current = dialog.querySelector('[data-dir-current]');
  const pickerTitle = dialog.querySelector('[data-picker-title]');
  const pickerHelp = dialog.querySelector('[data-picker-help]');
  const useDirectory = dialog.querySelector('[data-dir-use]');
  let target = null;
  let path = '/';
  let pickerMode = 'directory';
  let pickerFileKind = '';

  async function load(requestedPath, fallbackToRoot = false) {
    const response = await fetch(`/browse?path=${encodeURIComponent(requestedPath)}&mode=${pickerMode}&file_kind=${encodeURIComponent(pickerFileKind)}&server_mode=${encodeURIComponent(mode.value)}`);
    if (!response.ok) {
      if (fallbackToRoot && requestedPath !== '/') return load('/', false);
      list.innerHTML = '<p class="vl-danger-text"><vl-i18n key="setup.directory_unreadable"/></p>';
      return;
    }
    const data = await response.json();
    path = data.path;
    current.textContent = path;
    const up = dialog.querySelector('[data-dir-up]');
    up.disabled = !data.parent;
    up.dataset.parent = data.parent || '';
    list.innerHTML = '';
    for (const entry of data.entries) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'vl-dir-entry';
      button.dataset.entryType = entry.is_directory ? 'directory' : 'file';
      button.textContent = entry.name;
      button.addEventListener('click', () => {
        if (entry.is_directory) {
          load(entry.path);
        } else {
          target.value = entry.path;
          dialog.close();
        }
      });
      list.appendChild(button);
    }
    if (!data.entries.length) {
      list.innerHTML = `<p class="vl-muted">${pickerMode === 'file' ? '<vl-i18n key="setup.no_files_or_directories"/>' : '<vl-i18n key="setup.no_subdirectories"/>'}</p>`;
    }
  }

  function openPicker(button, mode) {
    pickerMode = mode;
    target = form.elements[button.dataset.dirPicker || button.dataset.filePicker];
    pickerFileKind = target?.name === 'tls_cert_file' ? 'certificate'
      : target?.name === 'tls_key_file' ? 'private_key' : '';
    const value = target?.value || '';
    path = value.startsWith('/') ? value : '/';
    if (pickerMode === 'file' && path !== '/') {
      path = path.slice(0, path.lastIndexOf('/')) || '/';
    }
    pickerTitle.textContent = pickerMode === 'file' ? '<vl-i18n key="setup.choose_file"/>' : '<vl-i18n key="setup.choose_directory"/>';
    pickerHelp.textContent = pickerMode === 'file'
      ? pickerFileKind === 'certificate'
        ? '<vl-i18n key="setup.certificate_files_help"/>'
        : '<vl-i18n key="setup.private_key_files_help"/>'
      : '<vl-i18n key="setup.server_directories_help"/>';
    useDirectory.hidden = pickerMode === 'file';
    load(path, true);
    dialog.showModal();
  }

  document.querySelectorAll('[data-dir-picker]').forEach(button => button.addEventListener('click', () => openPicker(button, 'directory')));
  document.querySelectorAll('[data-file-picker]').forEach(button => button.addEventListener('click', () => openPicker(button, 'file')));
  dialog.querySelector('[data-dir-close]').addEventListener('click', () => dialog.close());
  dialog.querySelector('[data-dir-up]').addEventListener('click', event => {
    if (event.currentTarget.dataset.parent) load(event.currentTarget.dataset.parent);
  });
  dialog.querySelector('[data-dir-use]').addEventListener('click', () => {
    if (target) {
      target.value = path;
      if (target === rootMountPath) syncAutomaticInternalDirectory();
      if (target === internalDirectory) internalDirectoryIsAutomatic = false;
    }
    dialog.close();
  });
});
