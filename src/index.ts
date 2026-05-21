/**
 * @module better-auth-multi-tenancy-rbac
 *
 * Server entry point. Import `rbac` to add the plugin to your Better Auth instance.
 * Import `hasPermission`, `hasAnyOnePermission`, and `hasAllPermissions` to evaluate
 * a user's effective permissions within a tenant from your application code or custom endpoints.
 *
 * The client plugin lives at the `better-auth-multi-tenancy-rbac/client` sub-path.
 */
export { rbac } from './plugin'
export {
  hasPermission,
  hasAnyOnePermission,
  hasAllPermissions,
} from './utils/permissions'

export type {
  Permission,
  TenantRole,
  TenantRolePermission,
  TenantMemberRole,
  RbacOptions,
} from './types/index'
