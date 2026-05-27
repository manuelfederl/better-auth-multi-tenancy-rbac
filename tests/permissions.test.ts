import { describe, it, expect, beforeEach } from 'vitest'
import {
  createMemoryDb,
  createTestAuth,
  createPermissionsAuth,
  seedPermission,
  seedTenant,
  signUpAndGetCookie,
  getSessionUserId,
  type MemoryDb,
  type TestAuth,
} from './setup'

describe('permissions — disabled by default', () => {
  let auth: TestAuth
  let cookie: string

  beforeEach(async () => {
    const db = createMemoryDb()
    auth = createTestAuth(db)
    cookie = await signUpAndGetCookie(auth, 'user@test.com')
  })

  it('createPermission returns FORBIDDEN when no authorization is configured', async () => {
    await expect(
      auth.api.createPermission({
        headers: { cookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      }),
    ).rejects.toThrow()
  })

  it('updatePermission returns FORBIDDEN when no authorization is configured', async () => {
    await expect(
      auth.api.updatePermission({
        headers: { cookie },
        params: { permissionId: 'any-id' },
        body: { name: 'x' },
      }),
    ).rejects.toThrow()
  })

  it('deletePermission returns FORBIDDEN when no authorization is configured', async () => {
    await expect(
      auth.api.deletePermission({
        headers: { cookie },
        params: { permissionId: 'any-id' },
      }),
    ).rejects.toThrow()
  })
})

describe('permissions — with authorization configured', () => {
  let db: MemoryDb
  let auth: TestAuth
  let adminCookie: string

  beforeEach(async () => {
    db = createMemoryDb()
    ;({ auth, adminCookie } = await createPermissionsAuth(db))
  })

  describe('POST /rbac/permissions (createPermission)', () => {
    it('creates a permission and returns it', async () => {
      const res = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })
      expect(res.permission).toMatchObject({
        name: 'invoice:read',
        resource: 'invoice',
        action: 'read',
      })
      expect(res.permission.id).toBeDefined()
    })

    it('creates a permission with an optional description', async () => {
      const res = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: {
          name: 'invoice:write',
          resource: 'invoice',
          action: 'write',
          description: 'Can write invoices',
        },
      })
      expect(res.permission.description).toBe('Can write invoices')
    })

    it('rejects duplicate name with CONFLICT', async () => {
      await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })
      await expect(
        auth.api.createPermission({
          headers: { cookie: adminCookie },
          body: { name: 'invoice:read', resource: 'invoice', action: 'list' },
        }),
      ).rejects.toThrow()
    })

    it('rejects duplicate (resource, action) pair with CONFLICT', async () => {
      await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })
      await expect(
        auth.api.createPermission({
          headers: { cookie: adminCookie },
          body: { name: 'invoice:read-v2', resource: 'invoice', action: 'read' },
        }),
      ).rejects.toThrow()
    })

    it('requires authentication', async () => {
      await expect(
        auth.api.createPermission({
          headers: {},
          body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('GET /rbac/permissions (listPermissions)', () => {
    it('returns all permissions including newly created ones', async () => {
      const before = (await auth.api.listPermissions({ headers: { cookie: adminCookie } })).permissions.length

      await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })
      await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:write', resource: 'invoice', action: 'write' },
      })

      const res = await auth.api.listPermissions({ headers: { cookie: adminCookie } })
      expect(res.permissions).toHaveLength(before + 2)
    })

    it('returns an empty array when no permissions are in the db', async () => {
      const emptyDb = createMemoryDb()
      const plainAuth = createTestAuth(emptyDb)
      const cookie = await signUpAndGetCookie(plainAuth, 'user@test.com')
      const res = await plainAuth.api.listPermissions({ headers: { cookie } })
      expect(res.permissions).toEqual([])
    })
  })

  describe('GET /rbac/permissions/:permissionId (getPermission)', () => {
    it('returns a single permission by id', async () => {
      const created = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })

      const res = await auth.api.getPermission({
        headers: { cookie: adminCookie },
        params: { permissionId: created.permission.id },
      })
      expect(res.permission.id).toBe(created.permission.id)
    })

    it('returns NOT_FOUND for unknown id', async () => {
      await expect(
        auth.api.getPermission({
          headers: { cookie: adminCookie },
          params: { permissionId: 'nonexistent' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('POST /rbac/permissions/:permissionId (updatePermission)', () => {
    it('updates a permission name', async () => {
      const created = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })

      const res = await auth.api.updatePermission({
        headers: { cookie: adminCookie },
        params: { permissionId: created.permission.id },
        body: { name: 'invoices:read' },
      })
      expect(res.permission?.name).toBe('invoices:read')
    })

    it('rejects a name that is already taken by another permission', async () => {
      const p1 = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })
      await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:write', resource: 'invoice', action: 'write' },
      })

      await expect(
        auth.api.updatePermission({
          headers: { cookie: adminCookie },
          params: { permissionId: p1.permission.id },
          body: { name: 'invoice:write' },
        }),
      ).rejects.toThrow()
    })

    it('returns NOT_FOUND for unknown id', async () => {
      await expect(
        auth.api.updatePermission({
          headers: { cookie: adminCookie },
          params: { permissionId: 'nonexistent' },
          body: { name: 'x' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('POST /rbac/permissions/:permissionId/delete (deletePermission)', () => {
    it('deletes a permission', async () => {
      const created = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })

      const res = await auth.api.deletePermission({
        headers: { cookie: adminCookie },
        params: { permissionId: created.permission.id },
      })
      expect(res.success).toBe(true)

      await expect(
        auth.api.getPermission({
          headers: { cookie: adminCookie },
          params: { permissionId: created.permission.id },
        }),
      ).rejects.toThrow()
    })

    it('also removes tenantRolePermission junction rows', async () => {
      const perm = await auth.api.createPermission({
        headers: { cookie: adminCookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      })

      const userId = await getSessionUserId(auth, adminCookie)
      seedTenant(db, 'cleanup-tenant', userId)

      await auth.api.createTenantRole({
        headers: { cookie: adminCookie },
        params: { tenantId: 'cleanup-tenant' },
        body: { name: 'Editor', permissionIds: [perm.permission.id] },
      })

      const junctionsBefore = db['tenantRolePermission'].length
      expect(junctionsBefore).toBeGreaterThan(0)

      await auth.api.deletePermission({
        headers: { cookie: adminCookie },
        params: { permissionId: perm.permission.id },
      })

      expect(db['tenantRolePermission']).toHaveLength(junctionsBefore - 1)
    })

    it('returns NOT_FOUND for unknown id', async () => {
      await expect(
        auth.api.deletePermission({
          headers: { cookie: adminCookie },
          params: { permissionId: 'nonexistent' },
        }),
      ).rejects.toThrow()
    })
  })

  describe('schema.permission.modelName option', () => {
    it('respects a custom modelName in the plugin schema definition', () => {
      const customAuth = createTestAuth(createMemoryDb(), {
        schema: { permission: { modelName: 'rbac_permission' } },
      })
      const plugin = customAuth.options.plugins?.find((p: { id: string }) => p.id === 'rbac') as {
        schema?: Record<string, { modelName?: string }>
      }
      expect(plugin?.schema?.['permission']?.modelName).toBe('rbac_permission')
    })
  })
})

describe('permissions — CRUD denied without the configured permission', () => {
  it('denies createPermission when the user lacks the configured permission', async () => {
    const db = createMemoryDb()
    seedPermission(db, 'perm-create', 'permission:create', 'permission', 'create')

    const auth = createTestAuth(db, {
      authorization: { permissions: { create: { resource: 'permission', action: 'create' } } },
    })
    const cookie = await signUpAndGetCookie(auth, 'user@test.com')

    await expect(
      auth.api.createPermission({
        headers: { cookie },
        body: { name: 'invoice:read', resource: 'invoice', action: 'read' },
      }),
    ).rejects.toThrow()
  })
})
