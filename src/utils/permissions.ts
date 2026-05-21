import type { Permission } from '../types/permission'
import type { TenantMemberRole } from '../types/tenant-member-role'
import type { TenantRolePermission } from '../types/tenant-role-permission'

interface TenantMember {
  id: string
  tenantId: string
  userId: string
}

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
