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
 * Checks whether the current session user has a single permission within the tenant.
 *
 * **Body**
 * - `permission` — the permission name to check (e.g. `"invoice:read"`).
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
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permission } = ctx.body
      const { user } = ctx.context.session

      const result = await hasPermission(ctx, tenantId, user.id, permission)

      return ctx.json({ result })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/permissions/check-any`
 *
 * Checks whether the current session user has **at least one** of the specified
 * permissions within the tenant.
 *
 * **Body**
 * - `permissions` — list of permission names; at least one must match.
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
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permissions } = ctx.body
      const { user } = ctx.context.session

      const result = await hasAnyOnePermission(ctx, tenantId, user.id, permissions)

      return ctx.json({ result })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/permissions/check-all`
 *
 * Checks whether the current session user has **all** of the specified permissions
 * within the tenant.
 *
 * **Body**
 * - `permissions` — list of permission names; every one must match.
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
      }),
    },
    async (ctx) => {
      const { tenantId } = ctx.params
      const { permissions } = ctx.body
      const { user } = ctx.context.session

      const result = await hasAllPermissions(ctx, tenantId, user.id, permissions)

      return ctx.json({ result })
    },
  )
