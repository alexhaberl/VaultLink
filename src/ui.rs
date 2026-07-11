//! Shared, build-free UI primitives for VaultLink's server-rendered pages.
//!
//! The stylesheet and SVGs are compiled into the binary. HTML helpers escape
//! every caller-provided value; route-specific markup remains in the owning
//! module so security-sensitive forms stay explicit.

/// Shared VaultLink stylesheet served by the application as `/assets/vaultlink.css`.
///
/// All component selectors are scoped below `.vl-ui` and all custom properties
/// use the `--vl-` prefix so screens can migrate incrementally without changing
/// legacy pages.
pub const STYLESHEET: &str = r#"
@layer vl-reset, vl-tokens, vl-base, vl-components, vl-layouts, vl-utilities;

@layer vl-tokens {
  :root {
    color-scheme: dark;
    --vl-navy-950: #070b16;
    --vl-navy-900: #0b1224;
    --vl-navy-850: #0b1326;
    --vl-navy-800: #111a2e;
    --vl-navy-750: #151f36;
    --vl-slate-600: #334565;
    --vl-blue-400: #5aa7ff;
    --vl-violet-400: #7c5cff;
    --vl-green-400: #55d69a;
    --vl-amber-400: #f4b95f;
    --vl-red-400: #ff7b86;
    --vl-white: #f3f7ff;

    --vl-canvas: var(--vl-navy-950);
    --vl-canvas-alt: var(--vl-navy-900);
    --vl-control: var(--vl-navy-850);
    --vl-surface: var(--vl-navy-800);
    --vl-surface-raised: var(--vl-navy-750);
    --vl-border: #263553;
    --vl-border-strong: var(--vl-slate-600);
    --vl-text: var(--vl-white);
    --vl-text-soft: #c8d6f4;
    --vl-text-muted: #9fb0d0;
    --vl-accent: var(--vl-blue-400);
    --vl-accent-2: var(--vl-violet-400);
    --vl-action-start: #2f67bd;
    --vl-action-end: #3974cf;
    --vl-focus: #8bc5ff;
    --vl-success: var(--vl-green-400);
    --vl-warning: var(--vl-amber-400);
    --vl-danger: var(--vl-red-400);

    --vl-font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
      "Segoe UI", sans-serif;
    --vl-font-mono: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    --vl-text-xs: 0.75rem;
    --vl-text-sm: 0.875rem;
    --vl-text-md: 1rem;
    --vl-text-lg: 1.125rem;
    --vl-text-xl: 1.5rem;
    --vl-text-2xl: clamp(2rem, 4vw, 3.4rem);

    --vl-space-1: 0.25rem;
    --vl-space-2: 0.5rem;
    --vl-space-3: 0.75rem;
    --vl-space-4: 1rem;
    --vl-space-5: 1.25rem;
    --vl-space-6: 1.5rem;
    --vl-space-7: 1.75rem;
    --vl-space-8: 2rem;
    --vl-space-10: 2.5rem;
    --vl-space-12: 3rem;

    --vl-radius-sm: 0.5rem;
    --vl-radius-md: 0.75rem;
    --vl-radius-lg: 1rem;
    --vl-radius-xl: 1.25rem;
    --vl-radius-pill: 999px;
    --vl-control-height: 2.75rem;
    --vl-content-max: 94rem;
    --vl-public-max: 76.25rem;

    --vl-shadow-sm: 0 10px 24px rgba(0, 0, 0, 0.2);
    --vl-shadow-panel: 0 22px 70px rgba(0, 0, 0, 0.34);
    --vl-shadow-overlay: 0 30px 90px rgba(0, 0, 0, 0.55);
    --vl-motion-fast: 140ms;
  }
}

@layer vl-reset {
  .vl-ui,
  .vl-ui *,
  .vl-ui *::before,
  .vl-ui *::after {
    box-sizing: border-box;
  }

  .vl-ui {
    min-width: 20rem;
    min-height: 100%;
    margin: 0;
  }

  .vl-ui img,
  .vl-ui svg {
    max-width: 100%;
  }

  .vl-ui button,
  .vl-ui input,
  .vl-ui select,
  .vl-ui textarea {
    font: inherit;
  }
}

@layer vl-base {
  .vl-ui {
    background:
      radial-gradient(circle at 12% -10%, rgba(90, 167, 255, 0.2), transparent 30rem),
      radial-gradient(circle at 88% 0%, rgba(124, 92, 255, 0.16), transparent 28rem),
      linear-gradient(135deg, var(--vl-canvas), var(--vl-canvas-alt) 62%, #080d1b);
    color: var(--vl-text);
    font-family: var(--vl-font-sans);
    font-size: var(--vl-text-md);
    line-height: 1.5;
  }

  .vl-ui [hidden] { display: none !important; }

  .vl-ui a {
    color: var(--vl-accent);
    text-underline-offset: 0.18em;
  }

  .vl-ui :where(a, button, input, select, textarea, summary):focus-visible {
    outline: 3px solid var(--vl-focus);
    outline-offset: 3px;
  }

  .vl-ui h1,
  .vl-ui h2,
  .vl-ui h3,
  .vl-ui p {
    overflow-wrap: anywhere;
  }

  .vl-ui h1 {
    margin: var(--vl-space-1) 0 var(--vl-space-3);
    font-size: var(--vl-text-2xl);
    line-height: 1.05;
    letter-spacing: -0.025em;
  }

  .vl-ui h2 {
    margin: 0 0 var(--vl-space-4);
    color: #dbeafe;
    font-size: var(--vl-text-lg);
    line-height: 1.25;
  }

  .vl-ui code {
    font-family: var(--vl-font-mono);
  }

  .vl-ui :where(input:not([type="checkbox"]):not([type="radio"]), select, textarea) {
    width: 100%;
    min-height: var(--vl-control-height);
    max-width: 100%;
    padding: var(--vl-space-3) var(--vl-space-3);
    border: 1px solid var(--vl-border-strong);
    border-radius: var(--vl-radius-md);
    background: var(--vl-control);
    color: var(--vl-text);
  }

  .vl-ui :where(input, select, textarea)::placeholder {
    color: var(--vl-text-muted);
    opacity: 0.86;
  }

  .vl-ui :where(input, select, textarea):disabled {
    cursor: not-allowed;
    opacity: 0.62;
  }
}

@layer vl-components {
  .vl-skip-link {
    position: fixed;
    z-index: 1000;
    top: var(--vl-space-3);
    left: var(--vl-space-3);
    padding: var(--vl-space-3) var(--vl-space-4);
    border-radius: var(--vl-radius-md);
    background: var(--vl-text);
    color: var(--vl-canvas);
    font-weight: 700;
    transform: translateY(-180%);
    transition: transform var(--vl-motion-fast) ease;
  }

  .vl-skip-link:focus {
    transform: translateY(0);
  }

  .vl-brand {
    display: inline-flex;
    align-items: center;
    gap: var(--vl-space-3);
    color: var(--vl-text);
    font-size: var(--vl-text-lg);
    font-weight: 800;
    letter-spacing: 0.01em;
    text-decoration: none;
  }

  .vl-brand__mark {
    display: inline-flex;
    width: 3rem;
    height: 3rem;
    flex: 0 0 3rem;
    filter: drop-shadow(0 12px 22px rgba(90, 167, 255, 0.2));
  }

  .vl-brand__copy {
    display: grid;
    line-height: 1.2;
  }

  .vl-brand__copy small {
    margin-top: var(--vl-space-1);
    color: var(--vl-text-muted);
    font-size: var(--vl-text-sm);
    font-weight: 600;
  }

  .vl-icon {
    width: 1.35em;
    height: 1.35em;
    flex: 0 0 auto;
    overflow: visible;
    vertical-align: -0.22em;
  }

  .vl-button,
  .vl-ui button {
    display: inline-flex;
    min-height: var(--vl-control-height);
    align-items: center;
    justify-content: center;
    gap: var(--vl-space-2);
    padding: var(--vl-space-3) var(--vl-space-4);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: var(--vl-radius-md);
    background: linear-gradient(135deg, var(--vl-action-start), var(--vl-action-end));
    box-shadow: 0 10px 24px rgba(47, 103, 189, 0.22);
    color: #fff;
    cursor: pointer;
    font-weight: 700;
    line-height: 1.15;
    text-decoration: none;
    transition: border-color var(--vl-motion-fast) ease, transform var(--vl-motion-fast) ease;
  }

  .vl-button:hover,
  .vl-ui button:hover {
    border-color: rgba(255, 255, 255, 0.32);
  }

  .vl-button:active,
  .vl-ui button:active {
    transform: translateY(1px);
  }

  .vl-button--secondary,
  .vl-ui button.vl-button--secondary {
    border-color: rgba(90, 167, 255, 0.38);
    background: rgba(90, 167, 255, 0.12);
    box-shadow: none;
    color: #dbeafe;
  }

  .vl-button--danger,
  .vl-ui button.vl-button--danger {
    border-color: rgba(255, 123, 134, 0.38);
    background: rgba(255, 123, 134, 0.14);
    box-shadow: none;
    color: #ffd6db;
  }

  .vl-button--small,
  .vl-ui button.vl-button--small {
    min-height: 2.5rem;
    padding: var(--vl-space-2) var(--vl-space-3);
    border-radius: var(--vl-radius-sm);
    font-size: var(--vl-text-sm);
  }

  .vl-ui button:disabled,
  .vl-button[aria-disabled="true"] {
    cursor: not-allowed;
    opacity: 0.52;
    transform: none;
  }

  .vl-panel,
  .vl-hero,
  .vl-form-card,
  .vl-setup-main > section {
    margin: var(--vl-space-4) 0;
    padding: var(--vl-space-5);
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: var(--vl-radius-xl);
    background: linear-gradient(180deg, rgba(21, 31, 54, 0.97), rgba(15, 23, 42, 0.97));
    box-shadow: var(--vl-shadow-panel);
  }

  .vl-panel, .vl-form-section { overflow: visible; }

  .vl-hero {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(17rem, 22.5rem);
    gap: var(--vl-space-6);
    align-items: center;
    background:
      linear-gradient(135deg, rgba(90, 167, 255, 0.15), rgba(124, 92, 255, 0.09)),
      linear-gradient(180deg, rgba(26, 39, 66, 0.98), rgba(17, 26, 46, 0.98));
  }

  .vl-eyebrow {
    margin: 0 0 var(--vl-space-2);
    color: #9ed0ff;
    font-size: var(--vl-text-xs);
    font-weight: 800;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }

  .vl-side-panel {
    padding: var(--vl-space-4);
    border: 1px solid rgba(255, 255, 255, 0.09);
    border-radius: var(--vl-radius-lg);
    background: rgba(255, 255, 255, 0.045);
  }

  .vl-form-card {
    box-shadow: none;
  }

  .vl-form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 15.625rem), 1fr));
    gap: var(--vl-space-4);
    align-items: end;
  }

  .vl-field,
  .vl-form-grid > label {
    display: grid;
    gap: var(--vl-space-1);
    margin: 0;
    color: var(--vl-text-soft);
    font-weight: 700;
  }

  .vl-field small,
  .vl-form-grid > label small {
    color: var(--vl-text-muted);
    font-size: var(--vl-text-sm);
    font-weight: 500;
  }

  .vl-input-action {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: var(--vl-space-2);
    align-items: end;
  }

  .vl-datetime-picker { position: relative; }
  .vl-datetime-popover {
    position: absolute;
    z-index: 40;
    top: calc(100% + var(--vl-space-2));
    right: 0;
    width: min(28rem, calc(100vw - 2rem));
    padding: var(--vl-space-4);
    border: 1px solid var(--vl-border-strong);
    border-radius: var(--vl-radius-lg);
    background: #0d182d;
    box-shadow: var(--vl-shadow-overlay);
  }
  .vl-datetime-popover[hidden] { display: none; }
  .vl-datetime-popover__grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: var(--vl-space-3);
  }
  .vl-datetime-popover__grid label { display: grid; gap: var(--vl-space-1); margin: 0; }
  .vl-datetime-popover__actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--vl-space-2);
    margin-top: var(--vl-space-4);
  }

  .vl-form-actions,
  .vl-button-group {
    display: flex;
    flex-wrap: wrap;
    gap: var(--vl-space-2);
    align-items: center;
  }

  .vl-panel-head {
    display: flex;
    justify-content: space-between;
    gap: var(--vl-space-4);
    align-items: flex-start;
  }
  .vl-panel-head p { margin-bottom: 0; }

  .vl-toggle {
    position: relative;
    display: flex;
    min-height: var(--vl-control-height);
    align-items: center;
    width: 100%;
    padding: var(--vl-space-3) var(--vl-space-4);
    border: 1px solid rgba(90, 167, 255, 0.24);
    border-radius: var(--vl-radius-lg);
    background: rgba(90, 167, 255, 0.07);
    color: var(--vl-text);
    cursor: pointer;
  }

  .vl-toggle > input {
    position: absolute;
    width: 1px;
    height: 1px;
    opacity: 0;
  }

  .vl-toggle > input + span {
    position: relative;
    display: grid;
    gap: var(--vl-space-1);
    padding-left: 4.25rem;
  }

  .vl-toggle > input + span::before {
    position: absolute;
    top: 50%;
    left: 0;
    width: 3.375rem;
    height: 1.875rem;
    border: 1px solid var(--vl-border-strong);
    border-radius: var(--vl-radius-pill);
    background: #1f2b45;
    box-shadow: inset 0 1px 4px rgba(0, 0, 0, 0.28);
    content: "";
    transform: translateY(-50%);
  }

  .vl-toggle > input + span::after {
    position: absolute;
    top: 50%;
    left: 0.25rem;
    width: 1.375rem;
    height: 1.375rem;
    border-radius: var(--vl-radius-pill);
    background: #dbeafe;
    content: "";
    transform: translateY(-50%);
    transition: transform var(--vl-motion-fast) ease;
  }

  .vl-toggle > input:checked + span::before {
    border-color: rgba(255, 255, 255, 0.2);
    background: linear-gradient(135deg, var(--vl-action-start), var(--vl-action-end));
  }

  .vl-toggle > input:checked + span::after {
    background: #fff;
    transform: translate(1.5rem, -50%);
  }

  .vl-toggle small {
    display: block;
    color: var(--vl-text-muted);
    font-size: var(--vl-text-sm);
    font-weight: 600;
    line-height: 1.35;
  }

  .vl-toggle:focus-within {
    outline: 3px solid var(--vl-focus);
    outline-offset: 3px;
  }

  .vl-alert {
    padding: var(--vl-space-3) var(--vl-space-4);
    border: 1px solid rgba(90, 167, 255, 0.28);
    border-radius: var(--vl-radius-md);
    background: rgba(90, 167, 255, 0.09);
    color: var(--vl-text-soft);
  }

  .vl-alert--danger {
    border-color: rgba(255, 123, 134, 0.3);
    background: rgba(255, 123, 134, 0.1);
    color: #ffd6db;
  }

  .vl-badge {
    display: inline-flex;
    min-height: 1.75rem;
    align-items: center;
    gap: var(--vl-space-1);
    padding: var(--vl-space-1) var(--vl-space-2);
    border: 1px solid rgba(90, 167, 255, 0.26);
    border-radius: var(--vl-radius-pill);
    background: rgba(90, 167, 255, 0.1);
    color: #cfe5ff;
    font-size: var(--vl-text-sm);
    font-weight: 650;
  }

  .vl-badge--success {
    border-color: rgba(85, 214, 154, 0.28);
    background: rgba(85, 214, 154, 0.1);
    color: #c8f8df;
  }

  .vl-badge--warning {
    border-color: rgba(244, 185, 95, 0.28);
    background: rgba(244, 185, 95, 0.1);
    color: #ffe2b2;
  }

  .vl-badge--danger {
    border-color: rgba(255, 123, 134, 0.3);
    background: rgba(255, 123, 134, 0.1);
    color: #ffd6db;
  }

  .vl-qr-card {
    display: inline-flex;
    margin: var(--vl-space-4) 0;
    padding: var(--vl-space-4);
    border-radius: var(--vl-radius-lg);
    background: #f8fbff;
    box-shadow: var(--vl-shadow-sm);
  }

  .vl-qr-card svg {
    display: block;
    width: 13.75rem;
    height: 13.75rem;
  }

  .vl-secret-block {
    display: grid;
    gap: var(--vl-space-2);
    margin: var(--vl-space-4) 0;
  }

  .vl-secret-block code {
    display: block;
    max-width: 100%;
    overflow: auto;
    padding: var(--vl-space-3);
    border: 1px solid var(--vl-border-strong);
    border-radius: var(--vl-radius-md);
    background: #081226;
    color: #dbeafe;
  }

  .vl-dir-dialog {
    width: min(45rem, 92vw);
    max-height: min(42rem, 86vh);
    padding: var(--vl-space-4);
    border: 1px solid rgba(90, 167, 255, 0.28);
    border-radius: var(--vl-radius-xl);
    background: #101a30;
    box-shadow: var(--vl-shadow-overlay);
    color: var(--vl-text);
  }

  .vl-dir-dialog::backdrop {
    background: rgba(0, 0, 0, 0.62);
  }

  .vl-dir-dialog__head {
    display: flex;
    justify-content: space-between;
    gap: var(--vl-space-4);
    align-items: center;
  }

  .vl-dir-list {
    display: grid;
    gap: var(--vl-space-2);
    max-height: 26.25rem;
    margin-top: var(--vl-space-4);
    overflow: auto;
  }

  .vl-ui button.vl-dir-entry {
    justify-content: space-between;
    width: 100%;
    border-color: rgba(255, 255, 255, 0.09);
    background: rgba(255, 255, 255, 0.04);
    box-shadow: none;
    color: var(--vl-text);
    text-align: left;
  }

}

@layer vl-layouts {
  .vl-setup-shell {
    min-height: 100vh;
  }

  .vl-setup-main {
    width: min(100%, var(--vl-public-max));
    margin: 0 auto;
    padding: var(--vl-space-8);
  }

  .vl-setup-header {
    margin-bottom: var(--vl-space-6);
  }

  /* 1200px: wide split layouts start stacking before controls become cramped. */
  @media (max-width: 75rem) {
    .vl-hero {
      grid-template-columns: minmax(0, 1fr) minmax(15rem, 20rem);
    }
  }

  /* 960px: shared shell breakpoint for compact navigation and setup grids. */
  @media (max-width: 60rem) {
    .vl-setup-main {
      padding: var(--vl-space-6);
    }

    .vl-hero {
      grid-template-columns: 1fr;
    }
  }

  /* 720px: forms and action groups become single-column touch layouts. */
  @media (max-width: 45rem) {
    :root {
      --vl-control-height: 3rem;
    }

    .vl-setup-main {
      padding: var(--vl-space-4);
    }

    .vl-panel,
    .vl-hero,
    .vl-form-card,
    .vl-setup-main > section {
      padding: var(--vl-space-4);
      border-radius: var(--vl-radius-lg);
    }

    .vl-form-grid,
    .vl-input-action {
      grid-template-columns: 1fr;
    }

    .vl-form-actions > *,
    .vl-input-action > .vl-button,
    .vl-input-action > button {
      width: 100%;
    }
  }

  /* 480px: compact brand and full-width primary actions. */
  @media (max-width: 30rem) {
    .vl-brand__mark {
      width: 2.75rem;
      height: 2.75rem;
      flex-basis: 2.75rem;
    }

    .vl-button-group {
      display: grid;
      grid-template-columns: 1fr;
    }

    .vl-button-group > *,
    .vl-form-actions > * {
      width: 100%;
    }

    .vl-dir-dialog__head {
      align-items: stretch;
      flex-direction: column;
    }
  }
}

@layer vl-utilities {
  .vl-muted {
    color: var(--vl-text-muted);
  }

  .vl-danger-text {
    color: var(--vl-danger);
  }

  .vl-sr-only {
    position: absolute !important;
    width: 1px !important;
    height: 1px !important;
    padding: 0 !important;
    border: 0 !important;
    margin: -1px !important;
    overflow: hidden !important;
    clip: rect(0, 0, 0, 0) !important;
    white-space: nowrap !important;
  }
}

@media (prefers-reduced-motion: reduce) {
  .vl-ui *,
  .vl-ui *::before,
  .vl-ui *::after {
    scroll-behavior: auto !important;
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
  }
}

/* Application shell and route-specific compositions. These remain namespaced
   so legacy SSR fragments can be migrated incrementally. */
@layer vl-components {
  .vl-button--ghost,
  .vl-ui button.vl-button--ghost {
    border-color: rgba(255, 255, 255, 0.1);
    background: rgba(255, 255, 255, 0.04);
    box-shadow: none;
    color: var(--vl-text-soft);
  }

  .vl-icon-button,
  .vl-ui button.vl-icon-button,
  .vl-ui summary.vl-icon-button {
    display: inline-flex;
    min-width: var(--vl-control-height);
    min-height: var(--vl-control-height);
    align-items: center;
    justify-content: center;
    padding: var(--vl-space-2);
    border: 1px solid var(--vl-border);
    border-radius: var(--vl-radius-md);
    background: rgba(255, 255, 255, 0.035);
    box-shadow: none;
    color: var(--vl-text-soft);
    cursor: pointer;
    list-style: none;
  }

  .vl-icon-button::-webkit-details-marker,
  .vl-action-details > summary::-webkit-details-marker {
    display: none;
  }

  .vl-stack { display: grid; gap: var(--vl-space-4); }
  .vl-inline-actions,
  .vl-topbar-actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--vl-space-2);
    align-items: center;
  }
  .vl-inline-actions form,
  .vl-topbar-actions form { margin: 0; }

  .vl-notice {
    padding: var(--vl-space-3) var(--vl-space-4);
    border: 1px solid var(--vl-border);
    border-radius: var(--vl-radius-md);
    background: rgba(90, 167, 255, 0.08);
  }
  .vl-notice--success { border-color: rgba(85, 214, 154, 0.28); color: #c8f8df; }
  .vl-notice--warning { border-color: rgba(244, 185, 95, 0.3); color: #ffe3ad; }
  .vl-notice--danger { border-color: rgba(255, 123, 134, 0.3); color: #ffd6db; }

  .vl-badge--accent { border-color: rgba(90, 167, 255, 0.35); background: rgba(90, 167, 255, 0.12); color: #cfe5ff; }
  .vl-badge--neutral { border-color: rgba(255, 255, 255, 0.12); background: rgba(255, 255, 255, 0.05); color: var(--vl-text-soft); }

  .vl-switch {
    position: relative;
    display: flex;
    min-height: var(--vl-control-height);
    align-items: center;
    width: 100%;
    padding: var(--vl-space-3) var(--vl-space-4);
    border: 1px solid rgba(90, 167, 255, 0.24);
    border-radius: var(--vl-radius-lg);
    background: rgba(90, 167, 255, 0.07);
    color: var(--vl-text);
    cursor: pointer;
  }
  .vl-switch > input { position: absolute; width: 1px; height: 1px; opacity: 0; }
  .vl-switch > input + span { position: relative; display: grid; gap: var(--vl-space-1); padding-left: 4.25rem; }
  .vl-switch > input + span::before {
    position: absolute; top: 50%; left: 0; width: 3.375rem; height: 1.875rem;
    border: 1px solid var(--vl-border-strong); border-radius: var(--vl-radius-pill);
    background: #1f2b45; content: ""; transform: translateY(-50%);
  }
  .vl-switch > input + span::after {
    position: absolute; top: 50%; left: 0.25rem; width: 1.375rem; height: 1.375rem;
    border-radius: 50%; background: #dbeafe; content: ""; transform: translateY(-50%);
    transition: transform var(--vl-motion-fast) ease;
  }
  .vl-switch > input:checked + span::before { border-color: rgba(255,255,255,.18); background: linear-gradient(135deg, var(--vl-action-start), var(--vl-action-end)); }
  .vl-switch > input:checked + span::after { transform: translate(1.5rem, -50%); background: #fff; }
  .vl-switch small { color: var(--vl-text-muted); font-size: var(--vl-text-sm); font-weight: 500; }

  .vl-stat-strip {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
    gap: 1px;
    margin: var(--vl-space-4) 0;
    overflow: hidden;
    border: 1px solid var(--vl-border);
    border-radius: var(--vl-radius-lg);
    background: var(--vl-border);
  }
  .vl-stat-strip > div { display: grid; gap: var(--vl-space-1); padding: var(--vl-space-5); background: rgba(12, 24, 45, .98); }
  .vl-stat-strip strong { font-size: var(--vl-text-xl); }
  .vl-stat-strip span { color: var(--vl-text-muted); font-size: var(--vl-text-sm); }

  .vl-toolbar { display: flex; gap: var(--vl-space-3); align-items: stretch; margin-bottom: var(--vl-space-5); }
  .vl-toolbar .vl-search { flex: 1 1 20rem; }
  .vl-toolbar > .vl-field:not(.vl-search) { flex: 0 1 12rem; }
  .vl-toolbar > .vl-button,
  .vl-toolbar > button { align-self: stretch; }

  .vl-data-table { width: 100%; border-collapse: collapse; }
  .vl-data-table th { padding: var(--vl-space-3); color: var(--vl-text-muted); font-size: var(--vl-text-xs); letter-spacing: .08em; text-align: left; text-transform: uppercase; }
  .vl-data-table td { padding: var(--vl-space-3); border-top: 1px solid rgba(255,255,255,.08); vertical-align: middle; }
  .vl-data-table tbody tr:hover { background: rgba(90,167,255,.045); }
  .vl-table-wrap { min-width: 0; overflow: visible; }

  @media (min-width: 45.01rem) {
    .vl-audit-table { table-layout: fixed; }
    .vl-audit-table .vl-audit-time { width: 8rem; }
    .vl-audit-table .vl-audit-user { width: 10rem; overflow-wrap: anywhere; word-break: break-word; }
    .vl-audit-table .vl-audit-action { width: 10rem; }
    .vl-audit-table .vl-audit-object { width: 11rem; overflow-wrap: anywhere; word-break: break-word; }
    .vl-audit-table .vl-audit-ip { width: 8rem; overflow-wrap: anywhere; }
    .vl-audit-table .vl-audit-action code { display: inline-block; max-width: 100%; white-space: normal; overflow-wrap: anywhere; word-break: break-word; }
    .vl-audit-table .vl-audit-detail { overflow-wrap: anywhere; word-break: break-word; }
  }

  .vl-file-select { display: block; color: var(--vl-text); font-weight: 650; cursor: pointer; }
  .vl-file-select > input { position: absolute; width: 1px; height: 1px; margin: 0; opacity: 0; overflow: hidden; }
  .vl-file-select > span { display: inline-flex; gap: var(--vl-space-3); align-items: center; min-height: 2.75rem; }
  .vl-button--small, .vl-ui button.vl-button--small { min-height: 2.75rem; }
  .vl-media-preview { display: block; max-width: 100%; }
  .vl-media-preview--image { height: auto; }
  .vl-media-preview--pdf { width: 100%; height: 75vh; border: 1px solid var(--vl-border); border-radius: var(--vl-radius-md); }
  .vl-security-facts dl { display: grid; gap: var(--vl-space-3); margin: 0; }
  .vl-security-facts dl > div { padding-block: var(--vl-space-3); border-bottom: 1px solid var(--vl-border); }
  .vl-security-facts dt { color: var(--vl-text-muted); font-size: var(--vl-text-xs); font-weight: 700; text-transform: uppercase; }
  .vl-security-facts dd { margin: var(--vl-space-1) 0 0; font-weight: 700; }
  .vl-file-select > input:focus-visible + span { outline: 3px solid var(--vl-focus); outline-offset: 3px; }
  .vl-file-select > input:checked + span { color: #b9d9ff; }

  .vl-action-details { position: relative; }
  .vl-action-details > summary { list-style: none; }
  .vl-action-panel {
    position: absolute; z-index: 20; top: calc(100% + var(--vl-space-2)); right: 0;
    display: grid; width: min(22rem, 85vw); gap: var(--vl-space-2); padding: var(--vl-space-3);
    border: 1px solid var(--vl-border-strong); border-radius: var(--vl-radius-lg);
    background: #0d182d; box-shadow: var(--vl-shadow-overlay);
  }
  .vl-action-panel > form > button, .vl-action-panel > a { width: 100%; }
  .vl-action-panel details { padding: var(--vl-space-2); border: 1px solid var(--vl-border); border-radius: var(--vl-radius-md); }

  .vl-copy-button { min-width: 6.5rem; }

  .vl-create-folder[open] > summary { display: none; }
  .vl-create-folder__form {
    display: grid;
    grid-template-columns: minmax(22rem, 1fr) auto;
    gap: var(--vl-space-2);
    align-items: end;
  }
  .vl-create-folder__field {
    display: grid;
    grid-template-columns: auto minmax(14rem, 1fr);
    gap: var(--vl-space-2);
    align-items: center;
  }
  .vl-create-folder__form > .vl-button,
  .vl-admin-create-form > .vl-button,
  .vl-browser-head .vl-inline-actions > .vl-button,
  .vl-browser-head .vl-inline-actions > details > summary {
    min-height: calc(1.5em + var(--vl-space-6) + 2px);
  }

  .vl-admin-create-form {
    display: grid;
    grid-template-columns: repeat(3, minmax(12rem, 1fr)) auto;
    gap: var(--vl-space-3);
    align-items: end;
  }
  .vl-admin-create-form > .vl-button { align-self: end; }

  .vl-upload-dialog { position: relative; }
  .vl-upload-dialog[open]::before {
    position: fixed;
    z-index: 29;
    inset: 0;
    background: rgba(2, 7, 18, .68);
    content: "";
  }
  .vl-upload-dialog > form {
    position: fixed;
    z-index: 30;
    top: 50%;
    left: 50%;
    width: min(32rem, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    padding: var(--vl-space-4);
    overflow: auto;
    border: 1px solid var(--vl-border-strong);
    border-radius: var(--vl-radius-lg);
    background: #0d182d;
    box-shadow: var(--vl-shadow-overlay);
    transform: translate(-50%, -50%);
  }
  .vl-upload-dialog .vl-upload-dropzone { padding: var(--vl-space-5); }
  .vl-upload-dialog [data-upload-submit] { width: 100%; }

  .vl-pagination { display: flex; flex-wrap: wrap; gap: var(--vl-space-3); align-items: center; justify-content: center; margin-top: var(--vl-space-5); }
  .vl-empty { padding: var(--vl-space-7); text-align: center; }
  .vl-selection-bar {
    position: sticky; z-index: 15; bottom: var(--vl-space-4); display: flex; gap: var(--vl-space-4);
    align-items: center; justify-content: space-between; margin-top: var(--vl-space-4); padding: var(--vl-space-4);
    border: 1px solid rgba(90,167,255,.35); border-radius: var(--vl-radius-lg);
    background: rgba(11, 25, 48, .97); box-shadow: var(--vl-shadow-overlay);
  }
  .vl-selection-bar[hidden] { display: none; }

  .vl-share-list { display: grid; border: 1px solid var(--vl-border); border-radius: var(--vl-radius-lg); overflow: visible; }
  .vl-share-row {
    position: relative; display: grid; grid-template-columns: minmax(13rem,1.2fr) minmax(15rem,1.4fr) minmax(13rem,1fr) minmax(13rem,.8fr) auto;
    gap: var(--vl-space-4); align-items: center; padding: var(--vl-space-4); border-bottom: 1px solid var(--vl-border);
  }
  .vl-share-row:last-child { border-bottom: 0; }
  .vl-share-identity, .vl-share-url, .vl-share-badges, .vl-share-quota { min-width: 0; }
  .vl-share-identity { display: flex; gap: var(--vl-space-3); align-items: center; }
  .vl-share-identity > div, .vl-share-quota { display: grid; gap: var(--vl-space-1); }
  .vl-share-url { display: flex; gap: var(--vl-space-2); align-items: center; }
  .vl-share-url code { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .vl-share-badges { display: flex; flex-wrap: wrap; gap: var(--vl-space-2); }
  .vl-share-quota progress, .vl-public-progress { width: 100%; height: .45rem; accent-color: var(--vl-accent); }

  .vl-segmented { display: grid; grid-template-columns: repeat(3,1fr); overflow: hidden; border: 1px solid var(--vl-border-strong); border-radius: var(--vl-radius-md); }
  .vl-segmented label { position: relative; cursor: pointer; }
  .vl-segmented input { position: absolute; opacity: 0; }
  .vl-segmented span { display: flex; min-height: var(--vl-control-height); align-items: center; justify-content: center; padding: var(--vl-space-3); border-right: 1px solid var(--vl-border); color: var(--vl-text-soft); }
  .vl-segmented label:last-child span { border-right: 0; }
  .vl-segmented input:checked + span { background: rgba(90,167,255,.16); color: #dbeafe; box-shadow: inset 0 0 0 1px var(--vl-accent); }
  .vl-target-card, .vl-browser-head { display: flex; gap: var(--vl-space-4); align-items: center; justify-content: space-between; }
  .vl-target-card > div { display: grid; gap: var(--vl-space-1); }
  .vl-form-section { padding: var(--vl-space-4); border: 1px solid var(--vl-border); border-radius: var(--vl-radius-lg); background: rgba(255,255,255,.025); }
  .vl-review-list { display: grid; margin: 0; }
  .vl-review-list > div { display: grid; grid-template-columns: 8rem minmax(0,1fr); gap: var(--vl-space-3); padding: var(--vl-space-3) 0; border-bottom: 1px solid var(--vl-border); }
  .vl-review-list dt { color: var(--vl-text-muted); }
  .vl-review-list dd { margin: 0; overflow-wrap: anywhere; }

  .vl-upload-dropzone {
    display: grid; min-height: 13rem; place-items: center; align-content: center; gap: var(--vl-space-3);
    padding: var(--vl-space-5); border: 2px dashed var(--vl-border-strong); border-radius: var(--vl-radius-lg);
    background: rgba(90,167,255,.025); text-align: center;
  }
  .vl-upload-dropzone[data-dragging="true"] { border-color: var(--vl-accent); background: rgba(90,167,255,.09); }
  .vl-upload-input { max-width: 100%; }
  .vl-upload-queue { display: grid; gap: var(--vl-space-2); margin: var(--vl-space-4) 0; }
  .vl-upload-item { display: grid; grid-template-columns: minmax(0,1fr) auto; gap: var(--vl-space-3); padding: var(--vl-space-3); border: 1px solid var(--vl-border); border-radius: var(--vl-radius-md); }

  .vl-audit-layout, .vl-public-share-layout, .vl-create-layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(18rem, .8fr); gap: var(--vl-space-5); align-items: start; }
  .vl-audit-layout { grid-template-columns: minmax(0, 3.4fr) minmax(17rem, .8fr); }
  .vl-create-layout { grid-template-columns: minmax(0, 1.8fr) minmax(19rem, .8fr); }
  .vl-review-card { position: sticky; top: var(--vl-space-4); }
  .vl-security-list { display: grid; margin: 0; }
  .vl-security-list > div { display: flex; justify-content: space-between; gap: var(--vl-space-3); padding: var(--vl-space-3) 0; border-bottom: 1px solid var(--vl-border); }
  .vl-security-list dd { margin: 0; text-align: right; }
}

@layer vl-layouts {
  .vl-app-shell { display: grid; grid-template-columns: 15.5rem minmax(0,1fr); min-height: 100vh; }
  .vl-sidebar { position: sticky; top: 0; display: flex; height: 100vh; flex-direction: column; gap: var(--vl-space-6); padding: var(--vl-space-8) var(--vl-space-5) var(--vl-space-5); border-right: 1px solid rgba(255,255,255,.08); background: rgba(7,15,29,.96); }
  .vl-nav { display: grid; gap: var(--vl-space-1); }
  .vl-nav-link { display: flex; min-height: var(--vl-control-height); align-items: center; gap: var(--vl-space-3); padding: var(--vl-space-3); border: 1px solid transparent; border-radius: var(--vl-radius-md); color: var(--vl-text-soft) !important; text-decoration: none; }
  .vl-nav-link:hover, .vl-nav-link[aria-current="page"] { border-color: rgba(90,167,255,.34); background: rgba(90,167,255,.11); color: var(--vl-accent) !important; }
  .vl-system-card { display: grid; gap: var(--vl-space-2); margin-top: auto; padding: var(--vl-space-4); border: 1px solid rgba(85,214,154,.2); border-radius: var(--vl-radius-lg); background: rgba(85,214,154,.06); color: var(--vl-text-muted); font-size: var(--vl-text-sm); overflow-wrap: anywhere; }
  .vl-system-card strong { color: var(--vl-success); }
  .vl-content { min-width: 0; padding: var(--vl-space-8) var(--vl-space-6); }
  .vl-topbar { display: flex; max-width: var(--vl-content-max); justify-content: space-between; gap: var(--vl-space-5); align-items: center; margin: 0 auto var(--vl-space-5); }
  .vl-main { width: min(100%, var(--vl-content-max)); margin: 0 auto; }
  .vl-public-shell { min-height: 100vh; padding: var(--vl-space-7); }
  .vl-public-header, .vl-public-main { width: min(100%, var(--vl-public-max)); margin: 0 auto; }
  .vl-public-header { display: flex; justify-content: space-between; gap: var(--vl-space-4); align-items: center; margin-bottom: var(--vl-space-5); }

  @media (max-width: 75rem) {
    .vl-share-row { grid-template-columns: minmax(12rem,1fr) minmax(14rem,1.2fr) minmax(12rem,1fr) auto; }
    .vl-share-quota { grid-column: 2 / 4; }
    .vl-audit-layout, .vl-public-share-layout, .vl-create-layout { grid-template-columns: 1fr; }
    .vl-review-card { position: static; }
  }
  @media (max-width: 60rem) {
    .vl-app-shell { display: block; }
    .vl-sidebar { position: relative; height: auto; gap: var(--vl-space-4); padding: var(--vl-space-6) var(--vl-space-4); border-right: 0; border-bottom: 1px solid var(--vl-border); }
    .vl-nav { display: flex; overflow-x: auto; }
    .vl-nav-link { flex: 0 0 auto; }
    .vl-system-card { display: none; }
    .vl-content { padding: var(--vl-space-6) var(--vl-space-4) var(--vl-space-4); }
    .vl-share-row { grid-template-columns: 1fr 1fr auto; }
    .vl-share-url, .vl-share-quota { grid-column: 1 / 3; }
  }
  @media (max-width: 45rem) {
    .vl-topbar, .vl-browser-head, .vl-panel-head, .vl-target-card, .vl-selection-bar { align-items: stretch; flex-direction: column; }
    .vl-topbar-actions, .vl-toolbar { display: grid; grid-template-columns: 1fr; }
    .vl-create-folder__form, .vl-admin-create-form, .vl-create-folder__field { grid-template-columns: 1fr; }
    .vl-topbar-actions > *, .vl-toolbar > *, .vl-selection-bar > * { width: 100%; }
    .vl-public-shell { padding: var(--vl-space-4); }
    .vl-public-header { align-items: flex-start; flex-direction: column; }
    .vl-segmented { grid-template-columns: 1fr; }
    .vl-segmented span { border-right: 0; border-bottom: 1px solid var(--vl-border); }
    .vl-share-row { display: grid; grid-template-columns: 1fr auto; }
    .vl-share-url, .vl-share-badges, .vl-share-quota { grid-column: 1 / -1; }
    .vl-data-table thead { display: none; }
    .vl-data-table, .vl-data-table tbody, .vl-data-table tr, .vl-data-table td { display: block; width: 100%; }
    .vl-data-table tr { margin-bottom: var(--vl-space-3); padding: var(--vl-space-3); border: 1px solid var(--vl-border); border-radius: var(--vl-radius-md); }
    .vl-data-table td { display: grid; grid-template-columns: 7rem minmax(0,1fr); gap: var(--vl-space-3); border: 0; }
    .vl-data-table td::before { color: var(--vl-text-muted); content: attr(data-label); font-size: var(--vl-text-xs); font-weight: 700; text-transform: uppercase; }
    .vl-datetime-popover {
      position: fixed;
      top: 50%;
      right: auto;
      left: 50%;
      max-height: calc(100vh - 2rem);
      overflow: auto;
      transform: translate(-50%, -50%);
    }
    .vl-datetime-popover__grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 30rem) {
    .vl-content, .vl-public-shell { padding: var(--vl-space-3); }
    .vl-panel { padding: var(--vl-space-4); }
  }
}
"#;

/// Compatibility-friendly name for consumers serving the shared application CSS.
pub const APP_CSS: &str = STYLESHEET;

/// Progressive enhancement for single-request upload forms.
///
/// The server-rendered form deliberately remains a single-file fallback. This
/// module enables multiple selection only after all queue controls were found
/// and initialized, then submits exactly one file part per request.
pub const UPLOAD_QUEUE_JAVASCRIPT: &str = r#"
(() => {
  "use strict";

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes < 1) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const value = bytes / (1024 ** unit);
    return `${value.toLocaleString("de-DE", { maximumFractionDigits: unit === 0 ? 0 : 1 })} ${units[unit]}`;
  };

  const outcomeText = (outcome) => {
    switch (outcome) {
      case "created": return "Hochgeladen";
      case "replaced": return "Ersetzt";
      case "created_uncertain": return "Hochgeladen – Persistenzbestätigung ausstehend";
      case "replaced_uncertain": return "Ersetzt – Persistenzbestätigung ausstehend";
      default: return "Hochgeladen";
    }
  };

  const initialize = (form, formIndex) => {
    if (!(form instanceof HTMLFormElement) || form.dataset.uploadQueueReady === "true") return;

    const input = form.querySelector("[data-upload-input]");
    const list = form.querySelector("[data-upload-list]");
    const dropzone = form.querySelector("[data-upload-dropzone]");
    const submit = form.querySelector("[data-upload-submit]");
    const endpoint = form.dataset.queueEndpoint;
    if (!(input instanceof HTMLInputElement) || input.type !== "file" || !input.name ||
        !(list instanceof HTMLElement) || !endpoint) return;

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
      setFeedback(items.length === 0 ? "Noch keine Datei ausgewählt." : "Datei aus der Warteschlange entfernt.");
    };

    const retryItem = async (item) => {
      if (running || item.status !== "error") return;
      item.status = "ready";
      item.message = "Bereit";
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
        name.textContent = item.serverFile || item.file.name;
        const meta = document.createElement("span");
        meta.className = "vl-muted";
        meta.textContent = `${formatBytes(item.file.size)} · ${item.message}`;
        description.append(name, meta);

        const actions = document.createElement("div");
        actions.className = "vl-inline";
        if (item.status === "error") {
          actions.append(actionButton("Erneut versuchen", () => { void retryItem(item); }, running));
        }
        actions.append(actionButton(
          item.status === "success" ? "Aus Liste entfernen" : "Entfernen",
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
        items.push({
          id: ++sequence,
          file,
          status: "ready",
          message: "Bereit",
          serverFile: "",
          outcome: ""
        });
      }
      render();
      if (files.length > 0) {
        setFeedback(`${files.length} ${files.length === 1 ? "Datei wurde" : "Dateien wurden"} hinzugefügt.`);
      }
    };

    const requestData = (item) => {
      const data = new FormData(form);
      for (const fileInput of form.querySelectorAll('input[type="file"][name]')) {
        data.delete(fileInput.name);
      }
      data.append(input.name, item.file, item.file.name);
      return data;
    };

    const uploadItem = async (item) => {
      item.status = "uploading";
      item.message = "Wird hochgeladen …";
      render();

      try {
        const response = await fetch(endpoint, {
          method: "POST",
          body: requestData(item),
          credentials: "same-origin",
          headers: { "Accept": "application/json" }
        });

        let payload;
        try {
          payload = await response.json();
        } catch (_) {
          throw new Error(response.ok ? "Ungültige Serverantwort" : `Upload fehlgeschlagen (${response.status})`);
        }

        if (!response.ok || (payload && payload.error)) {
          const error = payload && payload.error;
          const message = error && typeof error.message === "string"
            ? error.message
            : `Upload fehlgeschlagen (${response.status})`;
          const code = error && typeof error.code === "string" ? ` [${error.code}]` : "";
          throw new Error(`${message}${code}`);
        }
        if (!payload || typeof payload.file !== "string" || typeof payload.outcome !== "string") {
          throw new Error("Ungültige Serverantwort");
        }

        item.status = "success";
        item.serverFile = payload.file;
        item.outcome = payload.outcome;
        item.message = outcomeText(payload.outcome);
      } catch (error) {
        item.status = "error";
        item.message = error instanceof Error ? error.message : "Upload fehlgeschlagen";
      }
      render();
    };

    async function processItems(queue) {
      if (running || queue.length === 0) return;
      setBusy(true);
      render();
      for (const item of queue) {
        if (item.status === "ready" || item.status === "error") {
          await uploadItem(item);
        }
      }
      setBusy(false);
      render();

      const successful = queue.filter((item) => item.status === "success").length;
      const failed = queue.filter((item) => item.status === "error").length;
      const result = [`${successful} erfolgreich`];
      if (failed > 0) result.push(`${failed} fehlgeschlagen – einzeln erneut versuchen`);
      setFeedback(result.join(", "));
    }

    input.addEventListener("change", () => {
      addFiles(input.files);
      input.value = "";
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (running) return;
      const queue = items.filter((item) => item.status === "ready" || item.status === "error");
      if (queue.length === 0) {
        setFeedback(items.some((item) => item.status === "success")
          ? "Alle ausgewählten Dateien wurden bereits hochgeladen."
          : "Bitte mindestens eine Datei auswählen.");
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
    setFeedback("Noch keine Datei ausgewählt.");
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
"#;

/// Standalone VaultLink shield/link mark.
pub const LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="VaultLink"><defs><linearGradient id="vl-logo-g" x1="9" y1="7" x2="55" y2="59" gradientUnits="userSpaceOnUse"><stop stop-color="#5aa7ff"/><stop offset="1" stop-color="#7c5cff"/></linearGradient><filter id="vl-logo-s" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="6" stdDeviation="5" flood-color="#193b8f" flood-opacity=".35"/></filter></defs><rect width="64" height="64" rx="18" fill="#081226"/><path filter="url(#vl-logo-s)" d="M32 7 51 15v15c0 13-7.8 22.8-19 27-11.2-4.2-19-14-19-27V15L32 7Z" fill="url(#vl-logo-g)"/><path d="M24.4 36.7a7.5 7.5 0 0 1 0-10.6l4.1-4.1a7.5 7.5 0 0 1 10.6 0 2.8 2.8 0 0 1-4 4 1.9 1.9 0 0 0-2.7 0l-4.1 4.1a1.9 1.9 0 0 0 2.7 2.7 2.8 2.8 0 0 1 4 4 7.5 7.5 0 0 1-10.6-.1Z" fill="#f3f7ff"/><path d="M28.8 42a2.8 2.8 0 0 1 0-4 1.9 1.9 0 0 0 2.7 0l4.1-4.1a1.9 1.9 0 0 0-2.7-2.7 2.8 2.8 0 1 1-4-4 7.5 7.5 0 0 1 10.6 10.7L35.4 42a7.5 7.5 0 0 1-10.6 0Z" fill="#dbeafe" opacity=".95"/><path d="M27 32h10" stroke="#081226" stroke-width="4.2" stroke-linecap="round" opacity=".45"/></svg>"##;

/// Icons available to server-rendered UI helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icon {
    ArrowLeft,
    Audit,
    Calendar,
    Check,
    ChevronDown,
    Copy,
    Download,
    File,
    Folder,
    Link,
    Lock,
    Logout,
    More,
    Search,
    Server,
    Settings,
    Shield,
    Trash,
    Upload,
    Users,
    Warning,
}

impl Icon {
    fn paths(self) -> &'static str {
        match self {
            Self::ArrowLeft => r#"<path d="m15 18-6-6 6-6"/><path d="M9 12h10"/>"#,
            Self::Audit => {
                r#"<path d="M12 3 4.5 6v5.5c0 4.7 2.8 8 7.5 9.5 4.7-1.5 7.5-4.8 7.5-9.5V6L12 3Z"/><path d="m9.2 12 1.8 1.8 4-4"/>"#
            }
            Self::Calendar => {
                r#"<rect x="3.5" y="5.5" width="17" height="15" rx="2"/><path d="M8 3v5M16 3v5M3.5 10h17"/>"#
            }
            Self::Check => r#"<path d="m5 12.5 4.2 4.2L19 7"/>"#,
            Self::ChevronDown => r#"<path d="m7 9.5 5 5 5-5"/>"#,
            Self::Copy => {
                r#"<rect x="8" y="8" width="11" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2"/>"#
            }
            Self::Download => r#"<path d="M12 3v12M7.5 10.5 12 15l4.5-4.5"/><path d="M4 20h16"/>"#,
            Self::File => r#"<path d="M6 3.5h8l4 4V21H6Z"/><path d="M14 3.5V8h4"/>"#,
            Self::Folder => r#"<path d="M3.5 6.5h6l2 2h9v10.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2Z"/>"#,
            Self::Link => {
                r#"<path d="m9.5 14.5-1 1a4 4 0 1 1-5.7-5.7l3-3a4 4 0 0 1 5.7 0"/><path d="m14.5 9.5 1-1a4 4 0 1 1 5.7 5.7l-3 3a4 4 0 0 1-5.7 0"/><path d="m8.5 15.5 7-7"/>"#
            }
            Self::Lock => {
                r#"<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>"#
            }
            Self::Logout => {
                r#"<path d="M10 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5"/><path d="m15 8 4 4-4 4M19 12H9"/>"#
            }
            Self::More => {
                r#"<circle cx="5" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r="1" fill="currentColor" stroke="none"/>"#
            }
            Self::Search => r#"<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/>"#,
            Self::Server => {
                r#"<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.01M8 17h.01M12 7h5M12 17h5"/>"#
            }
            Self::Settings => {
                r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/>"#
            }
            Self::Shield => {
                r#"<path d="M12 3 4.5 6v5.5c0 4.7 2.8 8 7.5 9.5 4.7-1.5 7.5-4.8 7.5-9.5V6L12 3Z"/>"#
            }
            Self::Trash => r#"<path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/>"#,
            Self::Upload => r#"<path d="M12 16V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 20h16"/>"#,
            Self::Users => {
                r#"<circle cx="9" cy="8" r="3"/><path d="M3.5 20v-2a5.5 5.5 0 0 1 11 0v2M16 5.5a3 3 0 0 1 0 5.8M17 14a5 5 0 0 1 3.5 4.8V20"/>"#
            }
            Self::Warning => {
                r#"<path d="M10.3 4.5 2.8 18a2 2 0 0 0 1.8 3h14.8a2 2 0 0 0 1.8-3L13.7 4.5a2 2 0 0 0-3.4 0Z"/><path d="M12 9v5M12 18h.01"/>"#
            }
        }
    }
}

/// Render a decorative, non-focusable inline icon from a closed set of paths.
pub fn icon(icon: Icon) -> String {
    format!(
        r#"<svg class="vl-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{}</svg>"#,
        icon.paths()
    )
}

/// Render the shared brand lockup. The mark is decorative because the visible
/// product name immediately follows it.
pub fn brand_lockup(subtitle: &str) -> String {
    format!(
        r#"<div class="vl-brand"><span class="vl-brand__mark" aria-hidden="true">{LOGO_SVG}</span><span class="vl-brand__copy">VaultLink<small>{}</small></span></div>"#,
        escape_html(subtitle)
    )
}

/// Semantic badge variants with fixed class names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BadgeTone {
    Neutral,
    Success,
    Warning,
    Danger,
}

impl BadgeTone {
    fn class(self) -> &'static str {
        match self {
            Self::Neutral => "vl-badge",
            Self::Success => "vl-badge vl-badge--success",
            Self::Warning => "vl-badge vl-badge--warning",
            Self::Danger => "vl-badge vl-badge--danger",
        }
    }
}

/// Render an escaped status badge.
pub fn badge(tone: BadgeTone, text: &str) -> String {
    format!(
        r#"<span class="{}">{}</span>"#,
        tone.class(),
        escape_html(text)
    )
}

/// Render an escaped internal navigation link with a typed icon.
pub fn nav_link(href: &str, label: &str, icon_name: Icon, current: bool) -> String {
    let current = if current {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r#"<a class="vl-nav-link" href="{}"{}>{}<span>{}</span></a>"#,
        escape_html(href),
        current,
        icon(icon_name),
        escape_html(label)
    )
}

/// Escape text for HTML text and quoted attribute contexts.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stylesheet_contains_shared_breakpoints_and_accessibility_guards() {
        for breakpoint in ["75rem", "60rem", "45rem", "30rem"] {
            assert!(STYLESHEET.contains(breakpoint));
        }
        assert!(STYLESHEET.contains(":focus-visible"));
        assert!(STYLESHEET.contains("--vl-control-height: 2.75rem"));
        assert!(STYLESHEET.contains("prefers-reduced-motion"));
    }

    #[test]
    fn helpers_escape_all_caller_provided_copy() {
        let brand = brand_lockup(r#"<script>alert("x")</script>"#);
        assert!(!brand.contains("<script>"));
        assert!(brand.contains("&lt;script&gt;"));

        let nav = nav_link(r#"/admin?x="bad""#, "<Dateien>", Icon::Folder, true);
        assert!(nav.contains(r#"aria-current="page""#));
        assert!(nav.contains("&quot;bad&quot;"));
        assert!(nav.contains("&lt;Dateien&gt;"));
    }

    #[test]
    fn typed_icons_are_decorative_and_badges_are_escaped() {
        let folder = icon(Icon::Folder);
        assert!(folder.contains(r#"aria-hidden="true""#));
        assert!(folder.contains(r#"focusable="false""#));
        assert!(!folder.contains("<script"));

        let status = badge(BadgeTone::Danger, "<unsafe>");
        assert!(status.contains("vl-badge--danger"));
        assert!(status.contains("&lt;unsafe&gt;"));
    }
}
