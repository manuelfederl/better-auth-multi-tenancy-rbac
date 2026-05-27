import { createAuthEndpoint, sessionMiddleware } from 'better-auth/api'
import { APIError } from 'better-auth/api'
import { z } from 'zod'

import type { Permission } from '../types/permission'
import type { RbacOptions } from '../types/options'
import type { TenantRolePermission } from '../types/tenant-role-permission'
import { requireGlobalPermission } from '../utils/permissions'

/**
 * `POST /rbac/permissions`
 *
 * Creates a new global permission. The `name` must be unique across all permissions.
 * The `(resource, action)` pair must also be unique — it represents the semantic identity
 * of the permission (e.g. `resource: "invoice"`, `action: "read"` → `"invoice:read"`).
 *
 * **Errors**
 * - `CONFLICT` – name already taken.
 * - `CONFLICT` – a permission with the same (resource, action) pair already exists.
 */
export const createPermission = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/permissions',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        name: z.string().min(1),
        resource: z.string().min(1),
        action: z.string().min(1),
        description: z.string().optional(),
      }),
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const createRef = options.authorization?.permissions?.create
      if (!createRef) {
        throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
      }
      await requireGlobalPermission(ctx, user.id, createRef)

      const { name, resource, action, description } = ctx.body

      const existingByName = await ctx.context.adapter.findOne<Permission>({
        model: 'permission',
        where: [{ field: 'name', value: name }],
      })
      if (existingByName) {
        throw new APIError('CONFLICT', {
          message: 'A permission with this name already exists.',
        })
      }

      const existingByResourceAction = await ctx.context.adapter.findMany<Permission>({
        model: 'permission',
        where: [
          { field: 'resource', value: resource },
          { field: 'action', value: action },
        ],
      })
      if (existingByResourceAction.length > 0) {
        throw new APIError('CONFLICT', {
          message: 'A permission with this resource and action already exists.',
        })
      }

      const now = new Date()
      const permission = await ctx.context.adapter.create<Permission>({
        model: 'permission',
        data: {
          name,
          resource,
          action,
          ...(description !== undefined && { description }),
          createdAt: now,
          updatedAt: now,
        },
      })

      await options.onPermissionCreated?.(permission)

      return ctx.json({ permission })
    },
  )

/**
 * `GET /rbac/permissions`
 *
 * Returns all permissions. Any authenticated user may list permissions.
 */
export const listPermissions = () =>
  createAuthEndpoint(
    '/rbac/permissions',
    {
      method: 'GET',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const permissions = await ctx.context.adapter.findMany<Permission>({
        model: 'permission',
      })

      return ctx.json({ permissions })
    },
  )

/**
 * `GET /rbac/permissions/:permissionId`
 *
 * Returns a single permission by id.
 *
 * **Errors**
 * - `NOT_FOUND` – no permission with that id.
 */
export const getPermission = () =>
  createAuthEndpoint(
    '/rbac/permissions/:permissionId',
    {
      method: 'GET',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { permissionId } = ctx.params

      const permission = await ctx.context.adapter.findOne<Permission>({
        model: 'permission',
        where: [{ field: 'id', value: permissionId }],
      })

      if (!permission) {
        throw new APIError('NOT_FOUND', { message: 'Permission not found.' })
      }

      return ctx.json({ permission })
    },
  )

/**
 * `POST /rbac/permissions/:permissionId`
 *
 * Partially updates a permission. All fields are optional.
 * Re-checks name uniqueness and (resource, action) uniqueness, excluding the current row.
 *
 * **Errors**
 * - `NOT_FOUND` – no permission with that id.
 * - `CONFLICT`  – updated name is already taken by another permission.
 * - `CONFLICT`  – updated (resource, action) pair is already used by another permission.
 */
export const updatePermission = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/permissions/:permissionId',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        name: z.string().min(1).optional(),
        resource: z.string().min(1).optional(),
        action: z.string().min(1).optional(),
        description: z.string().optional(),
      }),
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const updateRef = options.authorization?.permissions?.update
      if (!updateRef) {
        throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
      }
      await requireGlobalPermission(ctx, user.id, updateRef)

      const { permissionId } = ctx.params
      const { name, resource, action, description } = ctx.body

      const existing = await ctx.context.adapter.findOne<Permission>({
        model: 'permission',
        where: [{ field: 'id', value: permissionId }],
      })
      if (!existing) {
        throw new APIError('NOT_FOUND', { message: 'Permission not found.' })
      }

      if (name !== undefined && name !== existing.name) {
        const conflict = await ctx.context.adapter.findOne<Permission>({
          model: 'permission',
          where: [{ field: 'name', value: name }],
        })
        if (conflict) {
          throw new APIError('CONFLICT', {
            message: 'A permission with this name already exists.',
          })
        }
      }

      const effectiveResource = resource ?? existing.resource
      const effectiveAction = action ?? existing.action
      if (
        effectiveResource !== existing.resource ||
        effectiveAction !== existing.action
      ) {
        const conflicts = await ctx.context.adapter.findMany<Permission>({
          model: 'permission',
          where: [
            { field: 'resource', value: effectiveResource },
            { field: 'action', value: effectiveAction },
          ],
        })
        const otherConflict = conflicts.find((p) => p.id !== permissionId)
        if (otherConflict) {
          throw new APIError('CONFLICT', {
            message: 'A permission with this resource and action already exists.',
          })
        }
      }

      const now = new Date()
      const permission = await ctx.context.adapter.update<Permission>({
        model: 'permission',
        where: [{ field: 'id', value: permissionId }],
        update: {
          ...(name !== undefined && { name }),
          ...(resource !== undefined && { resource }),
          ...(action !== undefined && { action }),
          ...(description !== undefined && { description }),
          updatedAt: now,
        },
      })

      if (permission) {
        await options.onPermissionUpdated?.(permission)
      }

      return ctx.json({ permission })
    },
  )

/**
 * `POST /rbac/permissions/:permissionId/delete`
 *
 * Deletes a permission. All `tenantRolePermission` junction rows referencing it
 * are explicitly removed first for adapter-agnostic safety (cascade handles it
 * for adapters that honour FK constraints).
 *
 * **Errors**
 * - `NOT_FOUND` – no permission with that id.
 */
export const deletePermission = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/permissions/:permissionId/delete',
    {
      method: 'POST',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const deleteRef = options.authorization?.permissions?.delete
      if (!deleteRef) {
        throw new APIError('FORBIDDEN', { message: 'Insufficient permissions.' })
      }
      await requireGlobalPermission(ctx, user.id, deleteRef)

      const { permissionId } = ctx.params

      const permission = await ctx.context.adapter.findOne<Permission>({
        model: 'permission',
        where: [{ field: 'id', value: permissionId }],
      })
      if (!permission) {
        throw new APIError('NOT_FOUND', { message: 'Permission not found.' })
      }

      // Explicit cleanup for adapter-agnostic safety
      const junctionRows = await ctx.context.adapter.findMany<TenantRolePermission>({
        model: 'tenantRolePermission',
        where: [{ field: 'permissionId', value: permissionId }],
      })
      await Promise.all(
        junctionRows.map((row) =>
          ctx.context.adapter.delete({
            model: 'tenantRolePermission',
            where: [{ field: 'id', value: row.id }],
          }),
        ),
      )

      await ctx.context.adapter.delete({
        model: 'permission',
        where: [{ field: 'id', value: permissionId }],
      })

      await options.onPermissionDeleted?.(permission)

      return ctx.json({ success: true })
    },
  )
