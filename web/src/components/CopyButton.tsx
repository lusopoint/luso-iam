import { useState } from "react";

import { useToast } from "./Toast";

/*
 * CopyButton: small inline button that copies `value` to the clipboard
 * and flashes a "Copied" state for 1.5s. Falls back to the older
 * document.execCommand("copy") path when the page isn't a secure
 * context (HTTP localhost in some browsers, embedded WebViews, etc.) —
 * the clipboard API requires a secure context.
 *
 * Used in places where the operator needs to grab a string fast:
 *   - new OIDC client secret (shown once, must be saved)
 *   - user IDs and key IDs in detail views
 *   - audit event metadata
 */

interface CopyButtonProps {
  /** Text to put on the clipboard. */
  value: string;
  /** Label shown next to the icon. Set to empty for icon-only. */
  label?: string;
  /** Extra Tailwind classes for the wrapper button. */
  className?: string;
  /** Optional: announce success via toast in addition to the inline flash. */
  toastOnSuccess?: boolean;
}

export default function CopyButton({
  value,
  label = "Copy",
  className = "",
  toastOnSuccess = false,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();

  async function onClick() {
    const ok = await copyToClipboard(value);
    if (!ok) {
      toast.error("Could not copy to clipboard.");
      return;
    }
    setCopied(true);
    if (toastOnSuccess) toast.success("Copied to clipboard.");
    // Reset after a beat so the next click flashes again. 1.5s feels
    // right — long enough to confirm, short enough to not stick.
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`${label || "Copy"} to clipboard`}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium
                  text-slate-500 transition hover:bg-slate-100 hover:text-slate-800
                  dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100
                  ${className}`}
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
      {label && <span>{copied ? "Copied" : label}</span>}
    </button>
  );
}

// ─── Clipboard plumbing ───────────────────────────────────────────────────

async function copyToClipboard(text: string): Promise<boolean> {
  // Primary path: async Clipboard API. Requires a secure context.
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or non-secure context — fall through to legacy.
    }
  }
  // Legacy path: temporary textarea + execCommand. Works in most
  // browsers, including non-secure-context dev setups.
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

// ─── Icons ────────────────────────────────────────────────────────────────

function ClipboardIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden className="h-3.5 w-3.5">
      <path d="M8 2a2 2 0 0 0-2 2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-1a2 2 0 0 0-2-2H8Zm0 2h4v1H8V4Z" />
    </svg>
  );
}
function CheckIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400">
      <path fillRule="evenodd" d="M16.7 5.3a1 1 0 0 1 0 1.4l-8 8a1 1 0 0 1-1.4 0l-4-4a1 1 0 1 1 1.4-1.4L8 12.6l7.3-7.3a1 1 0 0 1 1.4 0Z" clipRule="evenodd" />
    </svg>
  );
}
