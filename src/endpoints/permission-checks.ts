import { createAuthEndpoint, sessionMiddleware } from 'better-auth/api'
import { z } from 'zod'

import {
  hasPermission,
  hasAnyOnePermission,
  hasAllPermissions,
} from '../utils/permissions'

/**
 * `POST /rbac/tenants/:tenantId/permissions/check`
 *
 * Checks whether a user has a single permission within the tenant.
 * Defaults to the current session user when `userId` is omitted.
 *
 * **Body**
 * - `permission` — the permission name to check (e.g. `"invoice:read"`).
 * - `userId`     — optional; defaults to the authenticated user.
 *
 * **Returns**
 * `{ result: boolean }`
 */
export const checkPermission = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/permissions/check',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        permission: z.string().min(1),
        userId: z.string().optional(),
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permission, userId } = ctx.body
      const targetUserId = userId ?? ctx.context.session.user.id

      const result = await hasPermission(ctx, tenantId, targetUserId, permission)

      return ctx.json({ result })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/permissions/check-any`
 *
 * Checks whether a user has **at least one** of the specified permissions within
 * the tenant. Defaults to the current session user when `userId` is omitted.
 *
 * **Body**
 * - `permissions` — list of permission names; at least one must match.
 * - `userId`      — optional; defaults to the authenticated user.
 *
 * **Returns**
 * `{ result: boolean }`
 */
export const checkAnyPermission = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/permissions/check-any',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        permissions: z.array(z.string().min(1)).min(1),
        userId: z.string().optional(),
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permissions, userId } = ctx.body
      const targetUserId = userId ?? ctx.context.session.user.id

      const result = await hasAnyOnePermission(ctx, tenantId, targetUserId, permissions)

      return ctx.json({ result })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/permissions/check-all`
 *
 * Checks whether a user has **all** of the specified permissions within the tenant.
 * Defaults to the current session user when `userId` is omitted.
 *
 * **Body**
 * - `permissions` — list of permission names; every one must match.
 * - `userId`      — optional; defaults to the authenticated user.
 *
 * **Returns**
 * `{ result: boolean }`
 */
export const checkAllPermissions = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/permissions/check-all',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        permissions: z.array(z.string().min(1)).min(1),
        userId: z.string().optional(),
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permissions, userId } = ctx.body
      const targetUserId = userId ?? ctx.context.session.user.id

      const result = await hasAllPermissions(ctx, tenantId, targetUserId, permissions)

      return ctx.json({ result })
    },
  )
