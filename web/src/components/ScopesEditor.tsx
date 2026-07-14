import { Checkbox, TagInput } from "@lusopoint/luso-ui";

// the standard OIDC scopes an operator most commonly grants `offline_access`
// is what makes the server issue a refresh token, so it's called out here
// rather than left as an obscure custom entry
const STANDARD_SCOPES: { name: string; hint: string }[] = [
  { name: "openid", hint: "Required for OIDC. Requests an ID token." },
  { name: "profile", hint: "Profile claims (name, preferred_username, ...)." },
  { name: "email", hint: "The user's email and its verification status." },
  { name: "offline_access", hint: "Issues a refresh token for long-lived access." },
];

const STANDARD_NAMES = STANDARD_SCOPES.map((s) => s.name);

export const ScopesEditor = ({
  value,
  onChange,
}: {
  value: string[];
  onChange: (next: string[]) => void;
}) => {
  const customScopes = value.filter((s) => !STANDARD_NAMES.includes(s));

  const toggle = (scope: string, on: boolean) => {
    if (on) {
      if (!value.includes(scope)) onChange([...value, scope]);
    } else {
      onChange(value.filter((s) => s !== scope));
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {STANDARD_SCOPES.map((s) => (
          <Checkbox
            key={s.name}
            checked={value.includes(s.name)}
            onChange={(e) => toggle(s.name, e.target.checked)}
            label={s.name}
            description={s.hint}
          />
        ))}
      </div>

      <TagInput
        label="Custom scopes"
        value={customScopes}
        placeholder="e.g. billing:read"
        // only the custom half is handed to TagInput, so on change we splice it
        // back together with whichever standard scopes are currently ticked
        onChange={(next) => onChange([...value.filter((s) => STANDARD_NAMES.includes(s)), ...next])}
        validate={(candidate) =>
          STANDARD_NAMES.includes(candidate)
            ? "That's a standard scope — use the checkbox above."
            : /\s/.test(candidate)
              ? "Scopes cannot contain spaces."
              : null
        }
      />
    </div>
  );
}
