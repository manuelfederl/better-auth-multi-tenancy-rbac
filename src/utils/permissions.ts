import { APIError } from 'better-auth/api'
import type { Permission } from '../types/permission'
import type { TenantMember } from '../types/tenant-member'
import type { TenantMemberRole } from '../types/tenant-member-role'
import type { TenantRolePermission } from '../types/tenant-role-permission'
import type { PermissionRef } from '../types/options'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function getUserPermissions(ctx: any, tenantId: string, userId: string): Promise<Set<string>> {
  const member = (await ctx.context.adapter.findOne({
    model: 'tenantMember',
    where: [
      { field: 'tenantId', value: tenantId },
      { field: 'userId', value: userId },
    ],
  })) as TenantMember | null

  if (!member) return new Set()

  const assignments = (await ctx.context.adapter.findMany({
    model: 'tenantMemberRole',
    where: [{ field: 'tenantMemberId', value: member.id }],
  })) as TenantMemberRole[]

  if (assignments.length === 0) return new Set()

  const rolePermissionSets = await Promise.all(
    assignments.map((a) =>
      ctx.context.adapter.findMany({
        model: 'tenantRolePermission',
        where: [{ field: 'tenantRoleId', value: a.tenantRoleId }],
      }) as Promise<TenantRolePermission[]>,
    ),
  )

  const permissionIds = [
    ...new Set(rolePermissionSets.flat().map((rp) => rp.permissionId)),
  ]

  if (permissionIds.length === 0) return new Set()

  const permissions = await Promise.all(
    permissionIds.map(
      (id) =>
        ctx.context.adapter.findOne({
          model: 'permission',
          where: [{ field: 'id', value: id }],
        }) as Promise<Permission | null>,
    ),
  )

  const names = new Set<string>()
  for (const p of permissions) {
    if (p) names.add(p.name)
  }
  return names
}

/**
 * Looks up a permission by (resource, action) and verifies the user holds it in
 * the given tenant. Throws FORBIDDEN if the permission is not defined or if the
 * user does not have it. Used when a developer configures a custom authorization
 * override in RbacOptions.authorization.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireCustomPermission(
  ctx: any,
  tenantId: string,
  userId: string,
  ref: PermissionRef,
): Promise<void> {
  const matches = (await ctx.context.adapter.findMany({
    model: 'permission',
    where: [
      { field: 'resource', value: ref.resource },
      { field: 'action', value: ref.action },
    ],
  })) as Permission[]

  const perm = matches[0]
  if (!perm) {
    throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
  }

  const allowed = await hasPermission(ctx, tenantId, userId, perm.name)
  if (!allowed) {
    throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
  }
}

/**
 * Cross-tenant permission check for global operations (e.g. permission CRUD).
 * Scans every tenant the user belongs to and returns as soon as any of their
 * role assignments grants the permission referenced by `ref`.
 *
 * Throws FORBIDDEN if the permission record does not exist or the user does not
 * hold it in any tenant.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireGlobalPermission(
  ctx: any,
  userId: string,
  ref: PermissionRef,
): Promise<void> {
  const matches = (await ctx.context.adapter.findMany({
    model: 'permission',
    where: [
      { field: 'resource', value: ref.resource },
      { field: 'action', value: ref.action },
    ],
  })) as Permission[]

  const perm = matches[0]
  if (!perm) {
    throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
  }

  const memberships = (await ctx.context.adapter.findMany({
    model: 'tenantMember',
    where: [{ field: 'userId', value: userId }],
  })) as TenantMember[]

  for (const membership of memberships) {
    const assignments = (await ctx.context.adapter.findMany({
      model: 'tenantMemberRole',
      where: [{ field: 'tenantMemberId', value: membership.id }],
    })) as TenantMemberRole[]

    for (const assignment of assignments) {
      const rolePerms = (await ctx.context.adapter.findMany({
        model: 'tenantRolePermission',
        where: [
          { field: 'tenantRoleId', value: assignment.tenantRoleId },
          { field: 'permissionId', value: perm.id },
        ],
      })) as TenantRolePermission[]

      if (rolePerms.length > 0) return
    }
  }

  throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
}

/**
 * Returns true if the user has the specified permission in the given tenant.
 * A user's permissions are the union of all permissions from all their tenant roles.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function hasPermission(ctx: any, tenantId: string, userId: string, permission: string): Promise<boolean> {
  const perms = await getUserPermissions(ctx, tenantId, userId)
  return perms.has(permission)
}

/**
 * Returns true if the user has at least one of the specified permissions in the given tenant.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function hasAnyOnePermission(ctx: any, tenantId: string, userId: string, permissions: string[]): Promise<boolean> {
  const perms = await getUserPermissions(ctx, tenantId, userId)
  return permissions.some((p) => perms.has(p))
}

/**
 * Returns true if the user has every one of the specified permissions in the given tenant.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function hasAllPermissions(ctx: any, tenantId: string, userId: string, permissions: string[]): Promise<boolean> {
  const perms = await getUserPermissions(ctx, tenantId, userId)
  return permissions.every((p) => perms.has(p))
}
