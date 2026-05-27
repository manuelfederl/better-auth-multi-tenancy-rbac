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

describe('tenant-roles', () => {
  let db: MemoryDb
  let auth: TestAuth
  let ownerCookie: string
  let permissionId: string

  beforeEach(async () => {
    db = createMemoryDb()
    auth = createTestAuth(db)
    ownerCookie = await signUpAndGetCookie(auth, 'owner@test.com')
    const ownerId = await getSessionUserId(auth, ownerCookie)
    seedTenant(db, TENANT_ID, ownerId)

    permissionId = 'perm-invoice-read'
    seedPermission(db, permissionId, 'invoice:read', 'invoice', 'read')
  })

  describe('POST /rbac/tenants/:tenantId/roles (createTenantRole)', () => {
    it('creates a role with no permissions', async () => {
      const res = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Viewer' },
      })
      expect(res.role).toMatchObject({ name: 'Viewer', tenantId: TENANT_ID })
      expect(res.permissionIds).toEqual([])
    })

    it('creates a role with initial permissions', async () => {
      const res = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor', permissionIds: [permissionId] },
      })
      expect(res.permissionIds).toContain(permissionId)
    })

    it('rejects duplicate role name within the same tenant', async () => {
      await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Viewer' },
      })
      await expect(
        auth.api.createTenantRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID },
          body: { name: 'Viewer' },
        }),
      ).rejects.toThrow()
    })

    it('rejects unknown permissionIds with BAD_REQUEST', async () => {
      await expect(
        auth.api.createTenantRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID },
          body: { name: 'Editor', permissionIds: ['nonexistent'] },
        }),
      ).rejects.toThrow()
    })

    it('requires the caller to be the tenant owner', async () => {
      const memberCookie = await signUpAndGetCookie(auth, 'member@test.com')
      await expect(
        auth.api.createTenantRole({
          headers: { cookie: memberCookie },
          params: { tenantId: TENANT_ID },
          body: { name: 'Viewer' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('GET /rbac/tenants/:tenantId/roles (listTenantRoles)', () => {
    it('lists all roles for the tenant', async () => {
      await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Viewer' },
      })
      await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor' },
      })

      const res = await auth.api.listTenantRoles({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
      })
      expect(res.roles).toHaveLength(2)
    })

    it('requires the caller to be a tenant member', async () => {
      const outsiderCookie = await signUpAndGetCookie(auth, 'outsider@test.com')
      await expect(
        auth.api.listTenantRoles({
          headers: { cookie: outsiderCookie },
          params: { tenantId: TENANT_ID },
        }),
      ).rejects.toThrow()
    })
  })

  describe('GET /rbac/tenants/:tenantId/roles/:roleId (getTenantRole)', () => {
    it('returns a role with its permission ids', async () => {
      const created = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor', permissionIds: [permissionId] },
      })

      const res = await auth.api.getTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, roleId: created.role.id },
      })
      expect(res.role.id).toBe(created.role.id)
      expect(res.permissionIds).toContain(permissionId)
    })

    it('returns NOT_FOUND for unknown role', async () => {
      await expect(
        auth.api.getTenantRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID, roleId: 'nonexistent' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('POST /rbac/tenants/:tenantId/roles/:roleId (updateTenantRole)', () => {
    it('updates a role name', async () => {
      const created = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Viewer' },
      })

      const res = await auth.api.updateTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, roleId: created.role.id },
        body: { name: 'ReadOnly' },
      })
      expect(res.role?.name).toBe('ReadOnly')
    })

    it('fully replaces permissions when permissionIds is provided', async () => {
      const p2Id = 'perm-invoice-write'
      seedPermission(db, p2Id, 'invoice:write', 'invoice', 'write')
      const created = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor', permissionIds: [permissionId] },
      })

      const res = await auth.api.updateTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, roleId: created.role.id },
        body: { permissionIds: [p2Id] },
      })
      expect(res.permissionIds).toEqual([p2Id])
    })

    it('clears permissions when permissionIds is empty array', async () => {
      const created = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor', permissionIds: [permissionId] },
      })

      const res = await auth.api.updateTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, roleId: created.role.id },
        body: { permissionIds: [] },
      })
      expect(res.permissionIds).toEqual([])
    })
  })

  describe('POST /rbac/tenants/:tenantId/roles/:roleId/delete (deleteTenantRole)', () => {
    it('deletes a role and cleans up junction rows', async () => {
      const created = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Editor', permissionIds: [permissionId] },
      })

      const res = await auth.api.deleteTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, roleId: created.role.id },
      })
      expect(res.success).toBe(true)
      expect(db['tenantRolePermission']).toHaveLength(0)

      await expect(
        auth.api.getTenantRole({
          headers: { cookie: ownerCookie },
          params: { tenantId: TENANT_ID, roleId: created.role.id },
        }),
      ).rejects.toThrow()
    })
  })
})

describe('tenant-roles — custom authorization', () => {
  const VIEW_REF = { resource: 'tenant-roles', action: 'view' }
  const MANAGE_REF = { resource: 'tenant-roles', action: 'manage' }

  /**
   * Uses two auth instances backed by the same memory db:
   *  - setupAuth: no custom authorization, used for seeding data and creating
   *    roles/assignments (falls back to default owner/member checks).
   *  - testAuth: custom authorization enabled, the instance under test.
   *
   * Sessions created by setupAuth are valid in testAuth because both share the
   * same db and the same secret.
   */
  async function setupCustomAuth() {
    const db = createMemoryDb()
    const setupAuth = createTestAuth(db)
    const testAuth = createTestAuth(db, {
      authorization: { tenantRoles: { view: VIEW_REF, manage: MANAGE_REF } },
    })

    const ownerCookie = await signUpAndGetCookie(setupAuth, 'owner@test.com')
    const userCookie = await signUpAndGetCookie(setupAuth, 'user@test.com')
    const ownerId = await getSessionUserId(setupAuth, ownerCookie)
    const userId = await getSessionUserId(setupAuth, userCookie)
    seedTenant(db, TENANT_ID, ownerId, [userId])

    seedPermission(db, 'perm-tr-view', 'tenant-roles:view', 'tenant-roles', 'view')
    seedPermission(db, 'perm-tr-manage', 'tenant-roles:manage', 'tenant-roles', 'manage')
    const viewPerm = { permission: { id: 'perm-tr-view' } }
    const managePerm = { permission: { id: 'perm-tr-manage' } }

    const memberId = (db['tenantMember'].find(
      (m) => m['userId'] === userId,
    ) as Record<string, unknown>)['id'] as string

    return { setupAuth, testAuth, db, ownerCookie, userCookie, memberId, viewPerm, managePerm }
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

    const res = await testAuth.api.listTenantRoles({
      headers: { cookie: userCookie },
      params: { tenantId: TENANT_ID },
    })
    expect(res.roles).toBeDefined()
  })

  it('denies view access when the user lacks the configured permission', async () => {
    const { testAuth, userCookie } = await setupCustomAuth()

    await expect(
      testAuth.api.listTenantRoles({
        headers: { cookie: userCookie },
        params: { tenantId: TENANT_ID },
      }),
    ).rejects.toThrow()
  })

  it('grants manage access when the user holds the configured permission', async () => {
    const { setupAuth, testAuth, ownerCookie, userCookie, memberId, managePerm } =
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

    const res = await testAuth.api.createTenantRole({
      headers: { cookie: userCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'NewRole' },
    })
    expect(res.role.name).toBe('NewRole')
  })

  it('denies manage access when the user lacks the configured permission', async () => {
    const { testAuth, userCookie } = await setupCustomAuth()

    await expect(
      testAuth.api.createTenantRole({
        headers: { cookie: userCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'NewRole' },
      }),
    ).rejects.toThrow()
  })

  it('returns FORBIDDEN when the configured permission has not been defined in the DB', async () => {
    const db = createMemoryDb()
    const auth = createTestAuth(db, {
      authorization: {
        tenantRoles: { view: { resource: 'undefined-resource', action: 'undefined-action' } },
      },
    })
    const cookie = await signUpAndGetCookie(auth, 'user@test.com')
    const userId = await getSessionUserId(auth, cookie)
    seedTenant(db, TENANT_ID, userId)

    await expect(
      auth.api.listTenantRoles({
        headers: { cookie },
        params: { tenantId: TENANT_ID },
      }),
    ).rejects.toThrow()
  })
})
