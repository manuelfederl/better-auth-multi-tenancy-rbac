import { createAuthEndpoint, sessionMiddleware } from 'better-auth/api'
import { APIError } from 'better-auth/api'
import { z } from 'zod'

import type { TenantRole } from '../types/tenant-role'
import type { TenantMemberRole } from '../types/tenant-member-role'
import type { RbacOptions } from '../types/options'
import { requireTenantMember, requireTenantOwner } from './tenant-roles'

interface TenantMember {
  id: string
  tenantId: string
  userId: string
}

/**
 * `POST /rbac/tenants/:tenantId/members/:memberId/roles`
 *
 * Assigns a tenant role to a tenant member. The role must belong to the same
 * tenant as the member — cross-tenant role assignment is rejected.
 *
 * Only the tenant owner may assign roles.
 *
 * **Body**
 * - `tenantRoleId` — ID of the role to assign.
 *
 * **Errors**
 * - `NOT_FOUND`   – tenant, member, or role not found (or cross-tenant).
 * - `FORBIDDEN`   – caller is not the tenant owner.
 * - `CONFLICT`    – this role is already assigned to this member.
 */
export const assignRole = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/members/:memberId/roles',
    {
      method: 'POST',
      use: [sessionMiddleware],
      body: z.object({
        tenantRoleId: z.string(),
      }),
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, memberId } = ctx.params
      const { tenantRoleId } = ctx.body

      await requireTenantOwner(ctx, tenantId, user.id)

      const member = await ctx.context.adapter.findOne<TenantMember>({
        model: 'tenantMember',
        where: [{ field: 'id', value: memberId }],
      })
      if (!member || member.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', { message: 'Member not found.' })
      }

      const role = await ctx.context.adapter.findOne<TenantRole>({
        model: 'tenantRole',
        where: [{ field: 'id', value: tenantRoleId }],
      })
      if (!role || role.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', {
          message: 'Role not found in this tenant.',
        })
      }

      const existing = await ctx.context.adapter.findMany<TenantMemberRole>({
        model: 'tenantMemberRole',
        where: [
          { field: 'tenantMemberId', value: memberId },
          { field: 'tenantRoleId', value: tenantRoleId },
        ],
      })
      if (existing.length > 0) {
        throw new APIError('CONFLICT', {
          message: 'This role is already assigned to this member.',
        })
      }

      const now = new Date()
      const assignment = await ctx.context.adapter.create<TenantMemberRole>({
        model: 'tenantMemberRole',
        data: {
          tenantId,
          tenantMemberId: memberId,
          tenantRoleId,
          createdAt: now,
          updatedAt: now,
        },
      })

      await options.onRoleAssigned?.(assignment)

      return ctx.json({ assignment })
    },
  )

/**
 * `GET /rbac/tenants/:tenantId/members/:memberId/roles`
 *
 * Lists all role assignments for a given tenant member. Requires tenant membership.
 *
 * **Errors**
 * - `FORBIDDEN` – caller is not a member of this tenant.
 * - `NOT_FOUND` – member not found in this tenant.
 */
export const listMemberRoles = () =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/members/:memberId/roles',
    {
      method: 'GET',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, memberId } = ctx.params

      await requireTenantMember(ctx, tenantId, user.id)

      const member = await ctx.context.adapter.findOne<TenantMember>({
        model: 'tenantMember',
        where: [{ field: 'id', value: memberId }],
      })
      if (!member || member.tenantId !== tenantId) {
        throw new APIError('NOT_FOUND', { message: 'Member not found.' })
      }

      const assignments = await ctx.context.adapter.findMany<TenantMemberRole>({
        model: 'tenantMemberRole',
        where: [{ field: 'tenantMemberId', value: memberId }],
      })

      return ctx.json({ assignments })
    },
  )

/**
 * `POST /rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove`
 *
 * Removes a role assignment from a tenant member. The assignment must belong to
 * the specified member and tenant.
 *
 * Only the tenant owner may remove role assignments.
 *
 * **Errors**
 * - `NOT_FOUND` – assignment not found or does not belong to this member/tenant.
 * - `FORBIDDEN` – caller is not the tenant owner.
 */
export const removeRole = (options: RbacOptions) =>
  createAuthEndpoint(
    '/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove',
    {
      method: 'POST',
      use: [sessionMiddleware],
    },
    async (ctx) => {
      const { user } = ctx.context.session
      const { tenantId, memberId, assignmentId } = ctx.params

      await requireTenantOwner(ctx, tenantId, user.id)

      const assignment = await ctx.context.adapter.findOne<TenantMemberRole>({
        model: 'tenantMemberRole',
        where: [{ field: 'id', value: assignmentId }],
      })

      if (
        !assignment ||
        assignment.tenantMemberId !== memberId ||
        assignment.tenantId !== tenantId
      ) {
        throw new APIError('NOT_FOUND', { message: 'Role assignment not found.' })
      }

      await ctx.context.adapter.delete({
        model: 'tenantMemberRole',
        where: [{ field: 'id', value: assignmentId }],
      })

      await options.onRoleUnassigned?.(assignment)

      return ctx.json({ success: true })
    },
  )
