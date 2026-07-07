import { useState } from "react";

// The standard OIDC scopes an operator most commonly grants. `offline_access`
// is what makes the server issue a refresh token, so it's called out here
// rather than left as an obscure custom entry.
const STANDARD_SCOPES: { name: string; hint: string }[] = [
  { name: "openid", hint: "Required for OIDC. Requests an ID token." },
  { name: "profile", hint: "Profile claims (name, preferred_username, ...)." },
  { name: "email", hint: "The user's email and its verification status." },
  { name: "offline_access", hint: "Issues a refresh token for long-lived access." },
];

/**
 * ScopesEditor edits an OIDC client's allowed_scopes. Standard scopes are
 * offered as checkboxes; anything non-standard already on the client is shown
 * as a removable custom chip, and new custom scopes can be added by hand.
 *
 * `openid` is treated as effectively required — you can uncheck it, but the
 * hint makes clear OIDC needs it. We don't hard-block it, because the server
 * is the source of truth for validation.
 */
export function ScopesEditor({
  value,
  onChange,
}: {
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const [custom, setCustom] = useState("");

  const standardNames = STANDARD_SCOPES.map((s) => s.name);
  const customScopes = value.filter((s) => !standardNames.includes(s));

  function toggle(scope: string, on: boolean) {
    if (on) {
      if (!value.includes(scope)) onChange([...value, scope]);
    } else {
      onChange(value.filter((s) => s !== scope));
    }
  }

  function addCustom() {
    const s = custom.trim();
    if (s && !value.includes(s)) {
      onChange([...value, s]);
    }
    setCustom("");
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {STANDARD_SCOPES.map((s) => (
          <label key={s.name} className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              checked={value.includes(s.name)}
              onChange={(e) => toggle(s.name, e.target.checked)}
            />
            <span>
              <span className="font-mono text-slate-800 dark:text-slate-200">{s.name}</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">{s.hint}</span>
            </span>
          </label>
        ))}
      </div>

      {customScopes.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {customScopes.map((s) => (
            <span
              key={s}
              className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-mono text-slate-700 dark:bg-slate-800 dark:text-slate-200"
            >
              {s}
              <button
                type="button"
                onClick={() => toggle(s, false)}
                className="text-slate-400 hover:text-red-600"
                aria-label={`Remove scope ${s}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <input
          type="text"
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addCustom();
            }
          }}
          placeholder="custom scope"
          className="input flex-1 font-mono text-sm"
        />
        <button type="button" className="btn-secondary" onClick={addCustom}>
          Add scope
        </button>
      </div>
    </div>
  );
}
