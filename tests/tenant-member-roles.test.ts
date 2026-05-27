import { describe, it, expect, beforeEach } from 'vitest'
import {
  createMemoryDb,
  createTestAuth,
  signUpAndGetCookie,
  getSessionUserId,
  seedTenant,
  seedPermission,
  type MemoryDb,
} from './setup'

const TENANT_ID = 'tenant-1'

describe('tenant-member-roles', () => {
  let db: MemoryDb
  let auth: TestAuth
  let ownerCookie: string
  let memberCookie: string
  let memberId: string
  let roleId: string

  beforeEach(async () => {
    db = createMemoryDb()
    auth = createTestAuth(db)

    ownerCookie = await signUpAndGetCookie(auth, 'owner@test.com')
    memberCookie = await signUpAndGetCookie(auth, 'member@test.com')

    const ownerId = await getSessionUserId(auth, ownerCookie)
    const memberUserId = await getSessionUserId(auth, memberCookie)

    seedTenant(db, TENANT_ID, ownerId, [memberUserId])

    // memberId is the tenantMember row id for the non-owner user
    memberId = (db['tenantMember'].find(
      (m) => m['userId'] === memberUserId,
    ) as Record<string, unknown>)['id'] as string

    const role = await auth.api.createTenantRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'Editor' },
    })
    roleId = role.role.id
  })

  describe('POST /rbac/tenants/:tenantId/members/:memberId/roles (assignRole)', () => {
    it('assigns a role to a member', async () => {
      const res = await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: roleId },
      })
      expect(res.assignment).toMatchObject({ tenantMemberId: memberId, tenantRoleId: roleId })
    })

    it('rejects assigning the same role twice with CONFLICT', async () => {
      await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: roleId },
      })
      await expect(
        auth.api.assignRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID, memberId },
          body: { tenantRoleId: roleId },
        }),
      ).rejects.toThrow()
    })

    it('rejects cross-tenant role assignment with NOT_FOUND', async () => {
      const db2 = createMemoryDb()
      const auth2 = createTestAuth(db2)
      const owner2Cookie = await signUpAndGetCookie(auth2, 'owner2@test.com')
      const owner2Id = await getSessionUserId(auth2, owner2Cookie)
      seedTenant(db2, 'tenant-2', owner2Id)

      const otherRole = await auth2.api.createTenantRole({
        headers: { cookie: owner2Cookie },
        params: { tenantId: 'tenant-2' },
        body: { name: 'OtherRole' },
      })

      await expect(
        auth.api.assignRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID, memberId },
          body: { tenantRoleId: otherRole.role.id },
        }),
      ).rejects.toThrow()
    })

    it('requires the caller to be the tenant owner', async () => {
      await expect(
        auth.api.assignRole({
          headers: { cookie: memberCookie },
          params: { tenantId: TENANT_ID, memberId },
          body: { tenantRoleId: roleId },
        }),
      ).rejects.toThrow()
    })
  })

  describe('GET /rbac/tenants/:tenantId/members/:memberId/roles (listMemberRoles)', () => {
    it('lists all role assignments for a member', async () => {
      await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: roleId },
      })

      const res = await auth.api.listMemberRoles({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
      })
      expect(res.assignments).toHaveLength(1)
      expect(res.assignments[0]).toMatchObject({ tenantMemberId: memberId })
    })

    it('returns empty array when no roles are assigned', async () => {
      const res = await auth.api.listMemberRoles({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
      })
      expect(res.assignments).toEqual([])
    })
  })

  describe('POST /rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove (removeRole)', () => {
    it('removes a role assignment', async () => {
      const assigned = await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: roleId },
      })

      const res = await auth.api.removeRole({
        headers: { cookie: ownerCookie },
        params: {
          tenantId: TENANT_ID,
          memberId,
          assignmentId: assigned.assignment.id,
        },
      })
      expect(res.success).toBe(true)

      const list = await auth.api.listMemberRoles({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
      })
      expect(list.assignments).toHaveLength(0)
    })

    it('returns NOT_FOUND for unknown assignment', async () => {
      await expect(
        auth.api.removeRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID, memberId, assignmentId: 'nonexistent' },
        }),
      ).rejects.toThrow()
    })

    it('requires the caller to be the tenant owner', async () => {
      const assigned = await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: roleId },
      })

      await expect(
        auth.api.removeRole({
          headers: { cookie: memberCookie },
          params: {
            tenantId: TENANT_ID,
            memberId,
            assignmentId: assigned.assignment.id,
          },
        }),
      ).rejects.toThrow()
    })
  })
})

describe('tenant-member-roles — custom authorization', () => {
  const VIEW_REF = { resource: 'member-roles', action: 'view' }
  const MANAGE_REF = { resource: 'member-roles', action: 'manage' }

  async function setupCustomAuth() {
    const db = createMemoryDb()
    const setupAuth = createTestAuth(db)
    const testAuth = createTestAuth(db, {
      authorization: { tenantMemberRoles: { view: VIEW_REF, manage: MANAGE_REF } },
    })

    const ownerCookie = await signUpAndGetCookie(setupAuth, 'owner@test.com')
    const userCookie = await signUpAndGetCookie(setupAuth, 'user@test.com')
    const ownerId = await getSessionUserId(setupAuth, ownerCookie)
    const userId = await getSessionUserId(setupAuth, userCookie)
    seedTenant(db, TENANT_ID, ownerId, [userId])

    seedPermission(db, 'perm-mr-view', 'member-roles:view', 'member-roles', 'view')
    seedPermission(db, 'perm-mr-manage', 'member-roles:manage', 'member-roles', 'manage')
    const viewPerm = { permission: { id: 'perm-mr-view' } }
    const managePerm = { permission: { id: 'perm-mr-manage' } }

    const memberId = (db['tenantMember'].find(
      (m) => m['userId'] === userId,
    ) as Record<string, unknown>)['id'] as string

    const targetRole = await setupAuth.api.createTenantRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'SomeRole' },
    })

    return { setupAuth, testAuth, db, ownerCookie, userCookie, memberId, viewPerm, managePerm, targetRole }
  }

  it('grants view access when the user holds the configured permission', async () => {
    const { setupAuth, testAuth, ownerCookie, userCookie, memberId, viewPerm } =
      await setupCustomAuth()

    const viewRole = await setupAuth.api.createTenantRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'Viewer', permissionIds: [viewPerm.permission.id] },
    })
    await setupAuth.api.assignRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID, memberId },
      body: { tenantRoleId: viewRole.role.id },
    })

    const res = await testAuth.api.listMemberRoles({
      headers: { cookie: userCookie },
      params: { tenantId: TENANT_ID, memberId },
    })
    expect(res.assignments).toBeDefined()
  })

  it('denies view access when the user lacks the configured permission', async () => {
    const { testAuth, userCookie, memberId } = await setupCustomAuth()

    await expect(
      testAuth.api.listMemberRoles({
        headers: { cookie: userCookie },
        params: { tenantId: TENANT_ID, memberId },
      }),
    ).rejects.toThrow()
  })

  it('grants manage access when the user holds the configured permission', async () => {
    const { setupAuth, testAuth, ownerCookie, userCookie, memberId, managePerm, targetRole } =
      await setupCustomAuth()

    const manageRole = await setupAuth.api.createTenantRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'Manager', permissionIds: [managePerm.permission.id] },
    })
    await setupAuth.api.assignRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID, memberId },
      body: { tenantRoleId: manageRole.role.id },
    })

    const res = await testAuth.api.assignRole({
      headers: { cookie: userCookie },
      params: { tenantId: TENANT_ID, memberId },
      body: { tenantRoleId: targetRole.role.id },
    })
    expect(res.assignment).toBeDefined()
  })

  it('denies manage access when the user lacks the configured permission', async () => {
    const { testAuth, userCookie, memberId, targetRole } = await setupCustomAuth()

    await expect(
      testAuth.api.assignRole({
        headers: { cookie: userCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: targetRole.role.id },
      }),
    ).rejects.toThrow()
  })
})
