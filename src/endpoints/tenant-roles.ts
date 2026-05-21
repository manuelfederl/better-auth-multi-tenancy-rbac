import { createAuthEndpoint, sessionMiddleware } from 'better-auth/api'
import { APIError } from 'better-auth/api'
import { z } from 'zod'

import type { Permission } from '../types/permission'
import type { TenantRole } from '../types/tenant-role'
import type { TenantRolePermission } from '../types/tenant-role-permission'
import type { TenantMemberRole } from '../types/tenant-member-role'
import type { RbacOptions } from '../types/options'

interface Tenant {
  id: string
  ownerId: string | null
}

interface TenantMember {
  id: string
  tenantId: string
  userId: string
}

/**
 * Verifies the user is a member of the tenant.
 * Throws FORBIDDEN if not.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireTenantMember(
  ctx: any,
  tenantId: string,
  userId: string,
): Promise<TenantMember> {
  const member = (await ctx.context.adapter.findOne({
    model: 'tenantMember',
    where: [
      { field: 'tenantId', value: tenantId },
      { field: 'userId', value: userId },
    ],
  })) as TenantMember | null
  if (!member) {
    throw new APIError('FORBIDDEN', {
      message: 'You are not a member of this tenant.',
    })
  }
  return member
}

/**
 * Verifies the user is the owner of the tenant.
 * Throws NOT_FOUND if tenant doesn't exist, FORBIDDEN if not the owner.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireTenantOwner(
  ctx: any,
  tenantId: string,
  userId: string,
): Promise<Tenant> {
  const tenant = (await ctx.context.adapter.findOne({
    model: 'tenant',
    where: [{ field: 'id', value: tenantId }],
  })) as Tenant | null
  if (!tenant) {
    throw new APIError('NOT_FOUND', { message: 'Tenant not found.' })
  }
  if (tenant.ownerId !== userId) {
    throw new APIError('FORBIDDEN', {
      message: 'Only the tenant owner can perform this action.',
    })
  }
  return tenant
}

/**
 * `POST /rbac/tenants/:tenantId/roles`
 *
 * Creates a new role scoped to the given tenant. Optionally assigns an initial
 * set of permissions to the role via `permissionIds`.
 *
 * Only the tenant owner may create roles.
 *
 * **Body**
 * - `name`          — role name, must be unique within this tenant.
 * - `description`   — optional description.
 * - `permissionIds` — optional list of permission IDs to assign immediately.
 *
 * **Errors**
 * - `NOT_FOUND`   – tenant not found.
 * - `FORBIDDEN`   – caller is not the tenant owner.
 * - `CONFLICT`    – a role with this name already exists in this tenant.
 * - `BAD_REQUEST` – one or more permissionIds do not exist.
 */
export const createTenantRole = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/roles',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        permissionIds: z.array(z.string()).optional(),
      }),
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId } = ctx.params
      const { name, description, permissionIds } = ctx.body

      await requireTenantOwner(ctx, tenantId, user.id)

      const existingRoles = await ctx.context.adapter.findMany<TenantRole>({
        model: 'tenantRole',
        where: [
          { field: 'tenantId', value: tenantId },
          { field: 'name', value: name },
        ],
      })
      if (existingRoles.length > 0) {
        throw new APIError('CONFLICT', {
          message: 'A role with this name already exists in this tenant.',
        })
      }

      // Validate all permissionIds before creating anything
      const resolvedPermissions: Permission[] = []
      if (permissionIds && permissionIds.length > 0) {
        for (const permId of permissionIds) {
          const perm = await ctx.context.adapter.findOne<Permission>({
            model: 'permission',
            where: [{ field: 'id', value: permId }],
          })
          if (!perm) {
            throw new APIError('BAD_REQUEST', {
              message: `Permission with id "${permId}" not found.`,
            })
          }
          resolvedPermissions.push(perm)
        }
      }

      const now = new Date()
      const role = await ctx.context.adapter.create<TenantRole>({
        model: 'tenantRole',
        data: {
          name,
          ...(description !== undefined && { description }),
          tenantId,
          createdAt: now,
          updatedAt: now,
        },
      })

      const assignedPermissionIds: string[] = []
      if (resolvedPermissions.length > 0) {
        await Promise.all(
          resolvedPermissions.map(async (perm) => {
            await ctx.context.adapter.create<TenantRolePermission>({
              model: 'tenantRolePermission',
              data: {
                tenantRoleId: role.id,
                permissionId: perm.id,
                createdAt: now,
              },
            })
            assignedPermissionIds.push(perm.id)
          }),
        )
      }

      await options.onRoleCreated?.(role)

      return ctx.json({ role, permissionIds: assignedPermissionIds })
    },
  )

/**
 * `GET /rbac/tenants/:tenantId/roles`
 *
 * Lists all roles for the given tenant. Requires tenant membership.
 *
 * **Errors**
 * - `FORBIDDEN` – caller is not a member of this tenant.
 */
export const listTenantRoles = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/roles',
    {
      method: 'GET',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId } = ctx.params

      await requireTenantMember(ctx, tenantId, user.id)

      const roles = await ctx.context.adapter.findMany<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'tenantId', value: tenantId }],
      })

      return ctx.json({ roles })
    },
  )

/**
 * `GET /rbac/tenants/:tenantId/roles/:roleId`
 *
 * Returns a single tenant role along with its assigned permission IDs.
 * Requires tenant membership.
 *
 * **Errors**
 * - `FORBIDDEN`  – caller is not a member of this tenant.
 * - `NOT_FOUND`  – role does not exist in this tenant.
 */
export const getTenantRole = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/roles/:roleId',
    {
      method: 'GET',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, roleId } = ctx.params

      await requireTenantMember(ctx, tenantId, user.id)

      const role = await ctx.context.adapter.findOne<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'id', value: roleId }],
      })

      if (!role || role.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', { message: 'Role not found.' })
      }

      const junctionRows = await ctx.context.adapter.findMany<TenantRolePermission>({
        model: 'tenantRolePermission',
        where: [{ field: 'tenantRoleId', value: roleId }],
      })

      return ctx.json({
        role,
        permissionIds: junctionRows.map((r) => r.permissionId),
      })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/roles/:roleId`
 *
 * Updates a tenant role. All fields are optional.
 *
 * When `permissionIds` is provided, it **fully replaces** the current permission
 * assignments (all existing junction rows are deleted and the new set is inserted).
 * To clear all permissions, pass an empty array `[]`.
 *
 * Only the tenant owner may update roles.
 *
 * **Errors**
 * - `NOT_FOUND`   – tenant or role not found.
 * - `FORBIDDEN`   – caller is not the tenant owner.
 * - `CONFLICT`    – updated name is already used by another role in this tenant.
 * - `BAD_REQUEST` – one or more permissionIds do not exist.
 */
export const updateTenantRole = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/roles/:roleId',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        name: z.string().min(1).optional(),
        description: z.string().optional(),
        permissionIds: z.array(z.string()).optional(),
      }),
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, roleId } = ctx.params
      const { name, description, permissionIds } = ctx.body

      await requireTenantOwner(ctx, tenantId, user.id)

      const role = await ctx.context.adapter.findOne<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'id', value: roleId }],
      })
      if (!role || role.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', { message: 'Role not found.' })
      }

      if (name !== undefined && name !== role.name) {
        const conflicts = await ctx.context.adapter.findMany<TenantRole>({
          model: 'tenantRole',
          where: [
            { field: 'tenantId', value: tenantId },
            { field: 'name', value: name },
          ],
        })
        if (conflicts.some((r) => r.id !== roleId)) {
          throw new APIError('CONFLICT', {
            message: 'A role with this name already exists in this tenant.',
          })
        }
      }

      // Validate new permissionIds before making any changes
      const resolvedPermissions: Permission[] = []
      if (permissionIds !== undefined) {
        for (const permId of permissionIds) {
          const perm = await ctx.context.adapter.findOne<Permission>({
            model: 'permission',
            where: [{ field: 'id', value: permId }],
          })
          if (!perm) {
            throw new APIError('BAD_REQUEST', {
              message: `Permission with id "${permId}" not found.`,
            })
          }
          resolvedPermissions.push(perm)
        }
      }

      const now = new Date()
      const updatedRole = await ctx.context.adapter.update<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'id', value: roleId }],
        update: {
          ...(name !== undefined && { name }),
          ...(description !== undefined && { description }),
          updatedAt: now,
        },
      })

      let finalPermissionIds: string[] = []
      if (permissionIds !== undefined) {
        // Full replacement: delete all existing junction rows then re-insert
        const existing = await ctx.context.adapter.findMany<TenantRolePermission>({
          model: 'tenantRolePermission',
          where: [{ field: 'tenantRoleId', value: roleId }],
        })
        await Promise.all(
          existing.map((row) =>
            ctx.context.adapter.delete({
              model: 'tenantRolePermission',
              where: [{ field: 'id', value: row.id }],
            }),
          ),
        )

        await Promise.all(
          resolvedPermissions.map(async (perm) => {
            await ctx.context.adapter.create<TenantRolePermission>({
              model: 'tenantRolePermission',
              data: {
                tenantRoleId: roleId,
                permissionId: perm.id,
                createdAt: now,
              },
            })
          }),
        )
        finalPermissionIds = resolvedPermissions.map((p) => p.id)
      } else {
        // Return current permissionIds unchanged
        const current = await ctx.context.adapter.findMany<TenantRolePermission>({
          model: 'tenantRolePermission',
          where: [{ field: 'tenantRoleId', value: roleId }],
        })
        finalPermissionIds = current.map((r) => r.permissionId)
      }

      if (updatedRole) {
        await options.onRoleUpdated?.(updatedRole)
      }

      return ctx.json({ role: updatedRole, permissionIds: finalPermissionIds })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/roles/:roleId/delete`
 *
 * Deletes a tenant role. Explicitly removes all `tenantRolePermission` and
 * `tenantMemberRole` rows referencing it before deletion for adapter-agnostic safety.
 *
 * Only the tenant owner may delete roles.
 *
 * **Errors**
 * - `NOT_FOUND` – tenant or role not found.
 * - `FORBIDDEN` – caller is not the tenant owner.
 */
export const deleteTenantRole = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/roles/:roleId/delete',
    {
      method: 'POST',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, roleId } = ctx.params

      await requireTenantOwner(ctx, tenantId, user.id)

      const role = await ctx.context.adapter.findOne<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'id', value: roleId }],
      })
      if (!role || role.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', { message: 'Role not found.' })
      }

      // Explicit cleanup for adapter-agnostic safety
      const junctionRows = await ctx.context.adapter.findMany<TenantRolePermission>({
        model: 'tenantRolePermission',
        where: [{ field: 'tenantRoleId', value: roleId }],
      })
      await Promise.all(
        junctionRows.map((row) =>
          ctx.context.adapter.delete({
            model: 'tenantRolePermission',
            where: [{ field: 'id', value: row.id }],
          }),
        ),
      )

      const memberRoleRows = await ctx.context.adapter.findMany<TenantMemberRole>({
        model: 'tenantMemberRole',
        where: [{ field: 'tenantRoleId', value: roleId }],
      })
      await Promise.all(
        memberRoleRows.map((row) =>
          ctx.context.adapter.delete({
            model: 'tenantMemberRole',
            where: [{ field: 'id', value: row.id }],
          }),
        ),
      )

      await ctx.context.adapter.delete({
        model: 'tenantRole',
        where: [{ field: 'id', value: roleId }],
      })

      await options.onRoleDeleted?.(role)

      return ctx.json({ success: true })
    },
  )
