import { describe, it, expect, beforeEach } from 'vitest'
import {
  createMemoryDb,
  createTestAuth,
  signUpAndGetCookie,
  getSessionUserId,
  seedTenant,
  seedPermission,
  type MemoryDb,
  type TestAuth,
} from './setup'

const TENANT_ID = 'tenant-1'

describe('permission-checks', () => {
  let db: MemoryDb
  let auth: TestAuth
  let ownerCookie: string
  let memberCookie: string
  let memberId: string
  let permCounter = 0

  beforeEach(async () => {
    db = createMemoryDb()
    auth = createTestAuth(db)
    permCounter = 0

    ownerCookie = await signUpAndGetCookie(auth, 'owner@test.com')
    memberCookie = await signUpAndGetCookie(auth, 'member@test.com')

    const ownerId = await getSessionUserId(auth, ownerCookie)
    const memberUserId = await getSessionUserId(auth, memberCookie)

    seedTenant(db, TENANT_ID, ownerId, [memberUserId])

    memberId = (db['tenantMember'].find(
      (m) => m['userId'] === memberUserId,
    ) as Record<string, unknown>)['id'] as string
  })

  function seedAndGetPermId(name: string): string {
    const [resource, action] = name.split(':')
    const id = `perm-${++permCounter}`
    seedPermission(db, id, name, resource ?? name, action ?? 'any')
    return id
  }

  async function setupRoleWithPermissions(permissionNames: string[]) {
    const permIds = permissionNames.map((n) => seedAndGetPermId(n))

    const role = await auth.api.createTenantRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID },
      body: { name: 'TestRole', permissionIds: permIds },
    })

    await auth.api.assignRole({
      headers: { cookie: ownerCookie },
      params: { tenantId: TENANT_ID, memberId },
      body: { tenantRoleId: role.role.id },
    })
  }

  describe('POST /rbac/tenants/:tenantId/permissions/check', () => {
    it('returns true when the user has the permission', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permission: 'invoice:read' },
      })
      expect(res.result).toBe(true)
    })

    it('returns false when the user does not have the permission', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permission: 'invoice:write' },
      })
      expect(res.result).toBe(false)
    })

    it('returns false when the user has no roles assigned', async () => {
      seedAndGetPermId('invoice:read')

      const res = await auth.api.checkPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permission: 'invoice:read' },
      })
      expect(res.result).toBe(false)
    })

    it('always checks the current session user', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permission: 'invoice:read' },
      })
      expect(res.result).toBe(true)
    })
  })

  describe('POST /rbac/tenants/:tenantId/permissions/check-any', () => {
    it('returns true when the user has at least one of the permissions', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkAnyPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permissions: ['invoice:read', 'invoice:write'] },
      })
      expect(res.result).toBe(true)
    })

    it('returns false when the user has none of the permissions', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkAnyPermission({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permissions: ['invoice:write', 'invoice:delete'] },
      })
      expect(res.result).toBe(false)
    })
  })

  describe('POST /rbac/tenants/:tenantId/permissions/check-all', () => {
    it('returns true when the user has all of the permissions', async () => {
      await setupRoleWithPermissions(['invoice:read', 'invoice:write'])

      const res = await auth.api.checkAllPermissions({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permissions: ['invoice:read', 'invoice:write'] },
      })
      expect(res.result).toBe(true)
    })

    it('returns false when the user is missing any of the permissions', async () => {
      await setupRoleWithPermissions(['invoice:read'])

      const res = await auth.api.checkAllPermissions({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permissions: ['invoice:read', 'invoice:write'] },
      })
      expect(res.result).toBe(false)
    })

    it('reflects permissions from multiple roles (union)', async () => {
      const p1Id = seedAndGetPermId('invoice:read')
      const p2Id = seedAndGetPermId('invoice:write')

      const role1 = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Reader', permissionIds: [p1Id] },
      })
      const role2 = await auth.api.createTenantRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID },
        body: { name: 'Writer', permissionIds: [p2Id] },
      })

      await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: role1.role.id },
      })
      await auth.api.assignRole({
        headers: { cookie: ownerCookie },
        params: { tenantId: TENANT_ID, memberId },
        body: { tenantRoleId: role2.role.id },
      })

      const res = await auth.api.checkAllPermissions({
        headers: { cookie: memberCookie },
        params: { tenantId: TENANT_ID },
        body: { permissions: ['invoice:read', 'invoice:write'] },
      })
      expect(res.result).toBe(true)
    })
  })
})
