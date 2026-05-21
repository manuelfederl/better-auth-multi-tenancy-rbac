import type { Permission } from './permission'
import type { TenantRole } from './tenant-role'
import type { TenantMemberRole } from './tenant-member-role'

export interface RbacOptions {
  onPermissionCreated?: (permission: Permission) => Promise<void> | void
  onPermissionUpdated?: (permission: Permission) => Promise<void> | void
  onPermissionDeleted?: (permission: Permission) => Promise<void> | void

  onRoleCreated?: (role: TenantRole) => Promise<void> | void
  onRoleUpdated?: (role: TenantRole) => Promise<void> | void
  onRoleDeleted?: (role: TenantRole) => Promise<void> | void

  onRoleAssigned?: (assignment: TenantMemberRole) => Promise<void> | void
  onRoleUnassigned?: (assignment: TenantMemberRole) => Promise<void> | void
}
