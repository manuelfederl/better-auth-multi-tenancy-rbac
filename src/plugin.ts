import type { BetterAuthPlugin } from 'better-auth'

import { rbacSchema } from './schemas/index'
import type { RbacOptions } from './types/index'

import {
  createPermission,
  listPermissions,
  getPermission,
  updatePermission,
  deletePermission,
} from './endpoints/permissions'
import {
  createTenantRole,
  listTenantRoles,
  getTenantRole,
  updateTenantRole,
  deleteTenantRole,
} from './endpoints/tenant-roles'
import {
  assignRole,
  listMemberRoles,
  removeRole,
} from './endpoints/tenant-member-roles'
import {
  checkPermission,
  checkAnyPermission,
  checkAllPermissions,
} from './endpoints/permission-checks'

/**
 * Better Auth plugin that adds role-based access control (RBAC) to a multi-tenant
 * application. Designed to be used alongside `better-auth-multi-tenancy`.
 *
 * Registers four database tables (`permission`, `tenantRole`, `tenantRolePermission`,
 * `tenantMemberRole`) and 16 API endpoints covering global permission management,
 * per-tenant role management, member role assignment, and client-side permission checks.
 *
 * Server-side utility functions (`hasPermission`, `hasAnyOnePermission`,
 * `hasAllPermissions`) are exported from the main entry point for use in
 * application code and custom endpoints.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { multiTenancy } from "better-auth-multi-tenancy";
 * import { rbac } from "better-auth-multi-tenancy-rbac";
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     multiTenancy(),
 *     rbac({
 *       onPermissionCreated: async (permission) => {
 *         console.log(`Permission "${permission.name}" created`);
 *       },
 *       onRoleDeleted: async (role) => {
 *         console.log(`Role "${role.name}" deleted from tenant ${role.tenantId}`);
 *       },
 *       onRoleAssigned: async (assignment) => {
 *         console.log(`Role assigned to member ${assignment.tenantMemberId}`);
 *       },
 *     }),
 *   ],
 * });
 * ```
 */
export const rbac = (options: RbacOptions = {}) => {
  return {
    id: 'rbac',
    schema: rbacSchema,
    endpoints: {
      // Global permissions
      createPermission: createPermission(options),
      listPermissions: listPermissions(),
      getPermission: getPermission(),
      updatePermission: updatePermission(options),
      deletePermission: deletePermission(options),

      // Tenant roles
      createTenantRole: createTenantRole(options),
      listTenantRoles: listTenantRoles(),
      getTenantRole: getTenantRole(),
      updateTenantRole: updateTenantRole(options),
      deleteTenantRole: deleteTenantRole(options),

      // Member role assignments
      assignRole: assignRole(options),
      listMemberRoles: listMemberRoles(),
      removeRole: removeRole(options),

      // Client-side permission checks
      checkPermission: checkPermission(),
      checkAnyPermission: checkAnyPermission(),
      checkAllPermissions: checkAllPermissions(),
    },
  } satisfies BetterAuthPlugin
}
