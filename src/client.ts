import type { BetterAuthClientPlugin } from 'better-auth/client'

import type { rbac } from './plugin'

/**
 * Better Auth **client** plugin for RBAC.
 *
 * Pair this with {@link rbac} on the server. The `$InferServerPlugin` field carries
 * the server plugin's type at compile time so the client can infer all endpoint
 * signatures automatically.
 *
 * @example
 * ```ts
 * import { createAuthClient } from "better-auth/client";
 * import { rbacClient } from "better-auth-multi-tenancy-rbac/client";
 *
 * export const authClient = createAuthClient({
 *   plugins: [rbacClient()],
 * });
 *
 * // Usage:
 * const { data: { permission } } = await authClient.rbac.createPermission({
 *   name: "invoice:read",
 *   resource: "invoice",
 *   action: "read",
 * });
 *
 * const { data: { roles } } = await authClient.rbac.listTenantRoles({
 *   params: { tenantId: "tenant-id" },
 * });
 *
 * // Client-side permission checks:
 * const { data: { result } } = await authClient.rbac.checkPermission({
 *   params: { tenantId: "tenant-id" },
 *   body: { permission: "invoice:read" },
 * });
 * ```
 */
export const rbacClient = (): BetterAuthClientPlugin => {
  return {
    id: 'rbac',
    $InferServerPlugin: {} as ReturnType<typeof rbac>,
    pathMethods: {
      '/rbac/permissions': 'POST',
      '/rbac/permissions/:permissionId': 'POST',
      '/rbac/permissions/:permissionId/delete': 'POST',
      '/rbac/tenants/:tenantId/roles': 'POST',
      '/rbac/tenants/:tenantId/roles/:roleId': 'POST',
      '/rbac/tenants/:tenantId/roles/:roleId/delete': 'POST',
      '/rbac/tenants/:tenantId/members/:memberId/roles': 'POST',
      '/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove': 'POST',
      '/rbac/tenants/:tenantId/permissions/check': 'POST',
      '/rbac/tenants/:tenantId/permissions/check-any': 'POST',
      '/rbac/tenants/:tenantId/permissions/check-all': 'POST',
    },
  }
}
