import { betterAuth } from 'better-auth'
import type { BetterAuthPlugin } from 'better-auth'
import { memoryAdapter } from 'better-auth/adapters/memory'
import { rbac } from '../src/index'
import type { RbacOptions } from '../src/types/index'

/**
 * Minimal stub that registers the `tenant` and `tenantMember` schemas so the
 * memoryAdapter accepts queries to those models. The real data is seeded
 * directly into the db object via seedTenant().
 */
const multiTenancyStub = {
  id: 'multi-tenancy-stub',
  schema: {
    tenant: {
      fields: {
        ownerId: { type: 'string', required: false },
        createdAt: { type: 'date', required: false },
        updatedAt: { type: 'date', required: false },
      },
    },
    tenantMember: {
      fields: {
        tenantId: { type: 'string', required: true },
        userId: { type: 'string', required: true },
        createdAt: { type: 'date', required: false },
        updatedAt: { type: 'date', required: false },
      },
    },
  },
} satisfies BetterAuthPlugin

export type MemoryDb = Record<string, Record<string, unknown>[]>

export function createMemoryDb(): MemoryDb {
  return {
    user: [],
    session: [],
    account: [],
    verification: [],
    permission: [],
    tenantRole: [],
    tenantRolePermission: [],
    tenantMemberRole: [],
    tenant: [],
    tenantMember: [],
  }
}

export function createTestAuth(db: MemoryDb, options: RbacOptions = {}) {
  return betterAuth({
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    secret: 'test-secret-that-is-32-chars-minimum!!',
    baseURL: 'http://localhost:3000',
    plugins: [multiTenancyStub, rbac(options)],
  })
}

export type TestAuth = ReturnType<typeof createTestAuth>

export async function signUpAndGetCookie(
  auth: TestAuth,
  email: string,
  password = 'Password123!',
): Promise<string> {
  const res = await auth.api.signUpEmail({
    body: { email, password, name: email.split('@')[0] },
    asResponse: true,
  })
  const setCookie = res.headers.get('set-cookie')
  if (!setCookie) throw new Error('No session cookie in sign-up response')
  // "better-auth.session_token=abc; Path=/; ..." → "better-auth.session_token=abc"
  return setCookie.split(';')[0]
}

export async function getSessionUserId(auth: TestAuth, cookie: string): Promise<string> {
  const session = await auth.api.getSession({ headers: { cookie } })
  if (!session?.user?.id) throw new Error('No session user')
  return session.user.id
}

/**
 * Seeds a tenant and a member record directly into the memory db so that
 * requireTenantOwner / requireTenantMember work without the multi-tenancy plugin.
 */
export function seedTenant(
  db: MemoryDb,
  tenantId: string,
  ownerId: string,
  extraMemberIds: string[] = [],
) {
  db['tenant'].push({ id: tenantId, ownerId, createdAt: new Date(), updatedAt: new Date() })
  // Owner is also a member
  const memberIds = [ownerId, ...extraMemberIds]
  memberIds.forEach((userId, i) => {
    db['tenantMember'].push({
      id: `${tenantId}-member-${i}`,
      tenantId,
      userId,
      createdAt: new Date(),
      updatedAt: new Date(),
    })
  })
}

/**
 * Seeds a permission record directly into the memory db, bypassing the
 * createPermission endpoint (which is disabled by default).
 */
export function seedPermission(
  db: MemoryDb,
  id: string,
  name: string,
  resource: string,
  action: string,
) {
  db['permission'].push({ id, name, resource, action, createdAt: new Date(), updatedAt: new Date() })
}

const PERM_CREATE_REF = { resource: 'permission', action: 'create' }
const PERM_UPDATE_REF = { resource: 'permission', action: 'update' }
const PERM_DELETE_REF = { resource: 'permission', action: 'delete' }

/**
 * Creates a db + two auth instances where the permission write endpoints are
 * enabled. Returns the auth instance with CRUD gating plus an admin cookie
 * whose session user holds create/update/delete permissions.
 *
 * Implementation:
 *  - Meta-permissions are seeded directly into the db (no API call needed).
 *  - `setupAuth` (no custom options) is used to create the admin role and
 *    assign it, falling back to default owner checks.
 *  - `auth` has `authorization.permissions` configured and is the instance
 *    under test.
 */
export async function createPermissionsAuth(db: MemoryDb) {
  const createPermId = 'meta-perm-create'
  const updatePermId = 'meta-perm-update'
  const deletePermId = 'meta-perm-delete'
  seedPermission(db, createPermId, 'permission:create', 'permission', 'create')
  seedPermission(db, updatePermId, 'permission:update', 'permission', 'update')
  seedPermission(db, deletePermId, 'permission:delete', 'permission', 'delete')

  const setupAuth = createTestAuth(db)
  const auth = createTestAuth(db, {
    authorization: {
      permissions: {
        create: PERM_CREATE_REF,
        update: PERM_UPDATE_REF,
        delete: PERM_DELETE_REF,
      },
    },
  })

  const adminCookie = await signUpAndGetCookie(setupAuth, 'admin@test.com')
  const adminId = await getSessionUserId(setupAuth, adminCookie)

  const tenantId = 'permissions-admin-tenant'
  seedTenant(db, tenantId, adminId)

  const adminRole = await setupAuth.api.createTenantRole({
    headers: { cookie: adminCookie },
    params: { tenantId },
    body: { name: 'PermissionsAdmin', permissionIds: [createPermId, updatePermId, deletePermId] },
  })

  const memberId = (db['tenantMember'].find(
    (m) => m['userId'] === adminId,
  ) as Record<string, unknown>)['id'] as string

  await setupAuth.api.assignRole({
    headers: { cookie: adminCookie },
    params: { tenantId, memberId },
    body: { tenantRoleId: adminRole.role.id },
  })

  return { auth, adminCookie }
}
