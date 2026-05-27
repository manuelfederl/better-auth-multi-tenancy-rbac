import type { Permission } from './permission'
import type { TenantRole } from './tenant-role'
import type { TenantMemberRole } from './tenant-member-role'

export interface PermissionRef {
  resource: string
  action: string
}

export interface RbacOptions {
  schema?: {
    permission?: { modelName?: string }
    tenantRole?: { modelName?: string }
    tenantRolePermission?: { modelName?: string }
    tenantMemberRole?: { modelName?: string }
  }

  /**
   * Override the default owner/member authorization checks for tenant-scoped
   * endpoints with a RBAC permission lookup. When set, the system finds the
   * permission matching the given (resource, action) pair and verifies the
   * calling user holds it in the tenant. Falls back to the built-in owner or
   * member check when omitted.
   */
  authorization?: {
    /**
     * Guards the global permission write endpoints (createPermission, updatePermission,
     * deletePermission). When omitted these endpoints are **disabled** and return
     * FORBIDDEN — permissions must be seeded via the database instead.
     */
    permissions?: {
      /** Required to call createPermission. */
      create?: PermissionRef
      /** Required to call updatePermission. */
      update?: PermissionRef
      /** Required to call deletePermission. */
      delete?: PermissionRef
    }
    tenantRoles?: {
      /** Guards listTenantRoles and getTenantRole. Default: tenant membership. */
      view?: PermissionRef
      /** Guards createTenantRole, updateTenantRole, deleteTenantRole. Default: tenant ownership. */
      manage?: PermissionRef
    }
    tenantMemberRoles?: {
      /** Guards listMemberRoles. Default: tenant membership. */
      view?: PermissionRef
      /** Guards assignRole and removeRole. Default: tenant ownership. */
      manage?: PermissionRef
    }
  }

  onPermissionCreated?: (permission: Permission) => Promise<void> | void
  onPermissionUpdated?: (permission: Permission) => Promise<void> | void
  onPermissionDeleted?: (permission: Permission) => Promise<void> | void

  onRoleCreated?: (role: TenantRole) => Promise<void> | void
  onRoleUpdated?: (role: TenantRole) => Promise<void> | void
  onRoleDeleted?: (role: TenantRole) => Promise<void> | void

  onRoleAssigned?: (assignment: TenantMemberRole) => Promise<void> | void
  onRoleUnassigned?: (assignment: TenantMemberRole) => Promise<void> | void
}
