import { apiClient } from './client'
import type { McpStatus } from './types'

/**
 * The hosted MCP endpoint — `GET /api/v1/settings/mcp`.
 *
 * Read-only introspection: which path `/mcp` lives at, which tool/prompt/
 * resource names the current build exposes and which of the tools write.
 * The catalogue is compiled into the binary, so there is nothing to
 * configure here — the client config on the settings card only needs an
 * API key (`pwk_…`) to authenticate.
 */
export const mcpApi = {
  status: () => apiClient.get<McpStatus>('/settings/mcp'),
}

export const mcpKeys = {
  all: ['mcp'] as const,
  status: () => [...mcpKeys.all, 'status'] as const,
}

export default mcpApi
