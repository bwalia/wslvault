export function createFetcher(token: string | null, tenantId: string | null) {
  return async (url: string) => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    if (tenantId) headers['X-Tenant-Id'] = tenantId
    const res = await fetch(url, { headers })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error((err as { message?: string }).message ?? `Request failed: ${res.status}`)
    }
    return res.json()
  }
}

export async function mutate(
  url: string,
  method: string,
  body: unknown,
  token: string | null,
  tenantId: string | null,
) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (tenantId) headers['X-Tenant-Id'] = tenantId
  const res = await fetch(url, { method, headers, body: JSON.stringify(body) })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error((err as { message?: string }).message ?? `${method} failed: ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}
