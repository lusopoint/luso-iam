// cx joins truthy class names into one string. Cheaper than pulling in
// clsx, we have one call site per render at most
export const cx = (
  ...parts: Array<string | false | null | undefined>
): string => {
  return parts.filter(Boolean).join(' ')
}

// formatDateTime renders an ISO8601 string in the user's locale, short
// form. Returns "-" for empty / nullish input
export const formatDateTime = (iso: string | null | undefined): string => {
  if (!iso) return '-'
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// relativeTime renders e.g. "3 minutes ago". Falls back to absolute
// formatting for anything older than 7 days
export const relativeTime = (iso: string | null | undefined): string => {
  if (!iso) return '-'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso

  const diff = Date.now() - then
  const sec = Math.round(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`
  if (sec < 86400) return `${Math.round(sec / 3600)}h ago`
  if (sec < 7 * 86400) return `${Math.round(sec / 86400)}d ago`
  return formatDateTime(iso)
}

// shortID returns the first 8 chars of a UUID, with an ellipsis.
// Useful in dense tables where the full UUID overwhelms the layout
export const shortID = (id: string): string =>
  !id ? '' : id.length > 8 ? `${id.slice(0, 8)}...` : id

// validates a redirect URI for the TagInput on the client forms. Mirrors the
//server's check (absolute http/https, no fragment) so an operator finds out
// at the point of typing rather than on submit. The server still validates
// this is a nicety, not a security boundary
export const validRedirectURI = (candidate: string): string | null => {
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    return 'Must be an absolute URL.'
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return 'Must be http or https.'
  }
  if (url.hash) {
    return 'Must not contain a fragment (#).'
  }
  return null
}
