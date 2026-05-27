# better-auth-multi-tenancy-rbac

A [Better Auth](https://better-auth.com) plugin that adds role-based access control (RBAC) to multi-tenant applications. Designed to work alongside [better-auth-multi-tenancy](https://github.com/flt/better-auth-multi-tenancy).

## Features

- **Permission management** — define global permissions with a resource/action model
- **Tenant roles** — create roles scoped to individual tenants and assign permissions to them
- **Member role assignments** — assign any number of roles to tenant members
- **Permission evaluation** — server-side utilities to check a user's effective permissions within a tenant, with deduplication across overlapping roles
- **Custom authorization** — override the default owner/member checks on any endpoint group with your own RBAC permission
- **Full type safety** — server and client plugins with TypeScript inference
- **Database agnostic** — works with any Better Auth adapter (SQLite, PostgreSQL, MySQL, …)

## Installation

```bash
npm install @four-leaves/better-auth-multi-tenancy-rbac
```

## Setup

### 1. Server

Add the plugin to your Better Auth configuration alongside `better-auth-multi-tenancy`:

```ts
import { betterAuth } from 'better-auth'
import { multiTenancy } from '@four-leaves/better-auth-multi-tenancy'
import { rbac } from '@four-leaves/better-auth-multi-tenancy-rbac'

export const auth = betterAuth({
  // ... your existing config
  plugins: [
    multiTenancy(),
    rbac({
      // Optional: react to role assignments
      onRoleAssigned: async (assignment) => {
        console.log(
          `Role ${assignment.tenantRoleId} assigned to member ${assignment.tenantMemberId}`,
        )
      },
    }),
  ],
})
```

### 2. Database migration

Run the Better Auth migration to create the `permission`, `tenantRole`, `tenantRolePermission`, and `tenantMemberRole` tables:

```bash
npx better-auth migrate
```

Or generate the SQL without applying it:

```bash
npx better-auth generate
```

### 3. Client

Add the client plugin to your auth client:

```ts
import { createAuthClient } from 'better-auth/client'
import { rbacClient } from '@four-leaves/better-auth-multi-tenancy-rbac/client'

export const authClient = createAuthClient({
  // ... your existing config
  plugins: [rbacClient()],
})
```

All methods are available under `authClient.rbac.*`.

## Seeding Permissions

Permissions are global records that must exist in the database before they can be assigned to roles. **The `createPermission`, `updatePermission`, and `deletePermission` endpoints are disabled by default** — they return `403 Forbidden` unless you explicitly configure them in the plugin options (see [Authorization options](#authorization-options) below).

The recommended approach is to seed permissions in a database migration or a startup script that writes directly to the database, keeping the write surface closed to runtime API calls:

```ts
// Example: seed permissions during database migration / app bootstrap
await db.insert(permissionTable).values([
  { id: 'perm-1', name: 'invoice:read', resource: 'invoice', action: 'read' },
  { id: 'perm-2', name: 'invoice:write', resource: 'invoice', action: 'write' },
  {
    id: 'perm-3',
    name: 'invoice:delete',
    resource: 'invoice',
    action: 'delete',
  },
])
```

If your application needs to create permissions at runtime (e.g. through an admin UI), configure `authorization.permissions` with a `PermissionRef` for each operation you want to enable. Only users who hold the referenced permission in any of their tenants may call that endpoint.

## API Reference

### Permission Checks (Client-Side)

These endpoints let any client evaluate their own permissions without calling server-side utilities directly. Checks always apply to the **current session user** — there is no way to check another user's permissions through these endpoints.

| Method                | HTTP | Path                                            | Description                              |
| --------------------- | ---- | ----------------------------------------------- | ---------------------------------------- |
| `checkPermission`     | POST | `/rbac/tenants/:tenantId/permissions/check`     | Check a single permission                |
| `checkAnyPermission`  | POST | `/rbac/tenants/:tenantId/permissions/check-any` | Check if at least one permission matches |
| `checkAllPermissions` | POST | `/rbac/tenants/:tenantId/permissions/check-all` | Check if every permission matches        |

All three return `{ result: boolean }`.

**Check a single permission**

```ts
const { data } = await authClient.rbac.checkPermission({
  params: { tenantId: 'tenant-id' },
  body: { permission: 'invoice:read' },
})

if (!data.result) {
  // current user cannot read invoices
}
```

**Check if the user has at least one matching permission**

```ts
const { data } = await authClient.rbac.checkAnyPermission({
  params: { tenantId: 'tenant-id' },
  body: { permissions: ['invoice:read', 'invoice:write'] },
})
```

**Check if the user has all of the listed permissions**

```ts
const { data } = await authClient.rbac.checkAllPermissions({
  params: { tenantId: 'tenant-id' },
  body: { permissions: ['invoice:read', 'invoice:write', 'invoice:delete'] },
})
```

### Permissions

Permissions are global — they are not scoped to a tenant. Each permission represents a specific capability identified by a `resource` and `action` pair (e.g. `resource: "invoice"`, `action: "read"`). The `name` field is a unique human-readable key (e.g. `"invoice:read"`) used when evaluating access.

| Method             | HTTP | Path                                     | Description                                   |
| ------------------ | ---- | ---------------------------------------- | --------------------------------------------- |
| `createPermission` | POST | `/rbac/permissions`                      | Create a permission (**disabled by default**) |
| `listPermissions`  | GET  | `/rbac/permissions`                      | List all permissions                          |
| `getPermission`    | GET  | `/rbac/permissions/:permissionId`        | Get a permission by id                        |
| `updatePermission` | POST | `/rbac/permissions/:permissionId`        | Update a permission (**disabled by default**) |
| `deletePermission` | POST | `/rbac/permissions/:permissionId/delete` | Delete a permission (**disabled by default**) |

### Tenant Roles

Roles are scoped to a tenant. A role groups one or more permissions together so they can be assigned to members as a unit. When a role is created or updated, the full set of permission IDs is supplied — updating `permissionIds` always replaces the existing set.

| Method             | HTTP | Path                                           | Description                                            |
| ------------------ | ---- | ---------------------------------------------- | ------------------------------------------------------ |
| `createTenantRole` | POST | `/rbac/tenants/:tenantId/roles`                | Create a role in a tenant (owner only by default)      |
| `listTenantRoles`  | GET  | `/rbac/tenants/:tenantId/roles`                | List all roles in a tenant (members by default)        |
| `getTenantRole`    | GET  | `/rbac/tenants/:tenantId/roles/:roleId`        | Get a role and its permission IDs (members by default) |
| `updateTenantRole` | POST | `/rbac/tenants/:tenantId/roles/:roleId`        | Update a role (owner only by default)                  |
| `deleteTenantRole` | POST | `/rbac/tenants/:tenantId/roles/:roleId/delete` | Delete a role (owner only by default)                  |

**Create a role with permissions**

```ts
const { data } = await authClient.rbac.createTenantRole({
  params: { tenantId: 'tenant-id' },
  body: {
    name: 'Billing Manager',
    description: 'Can manage invoices and payments',
    permissionIds: ['permission-id-1', 'permission-id-2'],
  },
})
```

**Update a role's permissions (full replacement)**

```ts
await authClient.rbac.updateTenantRole({
  params: { tenantId: 'tenant-id', roleId: 'role-id' },
  body: {
    permissionIds: ['permission-id-1', 'permission-id-3'],
  },
})
```

### Member Role Assignments

A tenant member can hold any number of roles. Their effective permissions are the union of all permissions from all their assigned roles — overlapping permissions across roles are automatically deduplicated during evaluation.

| Method            | HTTP | Path                                                                   | Description                                           |
| ----------------- | ---- | ---------------------------------------------------------------------- | ----------------------------------------------------- |
| `assignRole`      | POST | `/rbac/tenants/:tenantId/members/:memberId/roles`                      | Assign a role to a member (owner only by default)     |
| `listMemberRoles` | GET  | `/rbac/tenants/:tenantId/members/:memberId/roles`                      | List a member's role assignments (members by default) |
| `removeRole`      | POST | `/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove` | Remove a role assignment (owner only by default)      |

**Assign a role to a member**

```ts
await authClient.rbac.assignRole({
  params: { tenantId: 'tenant-id', memberId: 'member-id' },
  body: { tenantRoleId: 'role-id' },
})
```

**List a member's roles**

```ts
const { data } = await authClient.rbac.listMemberRoles({
  params: { tenantId: 'tenant-id', memberId: 'member-id' },
})
```

## Permission Evaluation

The three server-side utility functions let you gate any server logic behind a permission check. Import them from the main entry point and call them from your own endpoints or middleware, passing the Better Auth endpoint context (`ctx`).

```ts
import {
  hasPermission,
  hasAnyOnePermission,
  hasAllPermissions,
} from '@four-leaves/better-auth-multi-tenancy-rbac'
```

A user's effective permissions are the union of all permissions granted by their tenant roles. Overlapping permissions across multiple roles are deduplicated automatically.

### `hasPermission`

Returns `true` if the user has the specified permission within the tenant.

```ts
const canRead = await hasPermission(ctx, tenantId, userId, 'invoice:read')

if (!canRead) {
  throw new APIError('FORBIDDEN', { message: 'You cannot view invoices.' })
}
```

### `hasAnyOnePermission`

Returns `true` if the user has **at least one** of the specified permissions.

```ts
const canManage = await hasAnyOnePermission(ctx, tenantId, userId, [
  'invoice:read',
  'invoice:write',
])
```

### `hasAllPermissions`

Returns `true` if the user has **every** permission in the list.

```ts
const isFullAdmin = await hasAllPermissions(ctx, tenantId, userId, [
  'invoice:read',
  'invoice:write',
  'invoice:delete',
])
```

## Plugin Options

```ts
rbac({
  // Optional: rename the database tables created by this plugin
  schema: {
    permission:           { modelName: "rbac_permission" },
    tenantRole:           { modelName: "rbac_tenant_role" },
    tenantRolePermission: { modelName: "rbac_tenant_role_permission" },
    tenantMemberRole:     { modelName: "rbac_tenant_member_role" },
  },

  // Optional: override default authorization checks (see below)
  authorization: { ... },

  // Optional: permission lifecycle hooks
  onPermissionCreated: async (permission) => { ... },
  onPermissionUpdated: async (permission) => { ... },
  onPermissionDeleted: async (permission) => { ... },

  // Optional: tenant role lifecycle hooks
  onRoleCreated: async (role) => { ... },
  onRoleUpdated: async (role) => { ... },
  onRoleDeleted: async (role) => { ... },

  // Optional: member role assignment lifecycle hooks
  onRoleAssigned:   async (assignment) => { ... },
  onRoleUnassigned: async (assignment) => { ... },
})
```

All callbacks are optional and may be async. The deleted-entity callbacks receive the record as it existed immediately before deletion.

## Authorization Options

The `authorization` block lets you replace the default owner/member checks on individual endpoint groups with a custom RBAC permission. The value is always a `PermissionRef` — an object with `resource` and `action` fields that identifies a permission record in the database.

```ts
import type { PermissionRef } from '@four-leaves/better-auth-multi-tenancy-rbac'

rbac({
  authorization: {
    // Enable runtime permission write endpoints (disabled by default)
    permissions: {
      create: { resource: 'permission', action: 'create' },
      update: { resource: 'permission', action: 'update' },
      delete: { resource: 'permission', action: 'delete' },
    },

    // Override guards on tenant role endpoints
    tenantRoles: {
      // replaces the default "must be a tenant member" check
      view: { resource: 'tenant-roles', action: 'view' },
      // replaces the default "must be the tenant owner" check
      manage: { resource: 'tenant-roles', action: 'manage' },
    },

    // Override guards on member role assignment endpoints
    tenantMemberRoles: {
      view: { resource: 'member-roles', action: 'view' },
      manage: { resource: 'member-roles', action: 'manage' },
    },
  },
})
```

### How it works

- **`authorization.permissions`** — when a `PermissionRef` is set for `create`, `update`, or `delete`, the corresponding endpoint performs a **cross-tenant** check: it scans all tenants the caller belongs to and returns `403 Forbidden` unless they hold the referenced permission in at least one of them. When the field is omitted, the endpoint is disabled entirely.

- **`authorization.tenantRoles` / `authorization.tenantMemberRoles`** — when a `PermissionRef` is set, the endpoint performs a **tenant-scoped** check: the caller must hold the referenced permission within the specific tenant being accessed. When the field is omitted, the endpoint falls back to the built-in check (tenant ownership for write operations, tenant membership for read operations).

The permission record referenced by a `PermissionRef` must already exist in the database. If it cannot be found, the endpoint returns `403 Forbidden`.

### Example: enabling runtime permission management

This pattern seeds the three meta-permissions at migration time and enables the write endpoints for users who hold an `admin` role:

```ts
// In your database seed / migration:
await db.insert(permissionTable).values([
  { name: 'permission:create', resource: 'permission', action: 'create' },
  { name: 'permission:update', resource: 'permission', action: 'update' },
  { name: 'permission:delete', resource: 'permission', action: 'delete' },
])

// In your auth config:
rbac({
  authorization: {
    permissions: {
      create: { resource: 'permission', action: 'create' },
      update: { resource: 'permission', action: 'update' },
      delete: { resource: 'permission', action: 'delete' },
    },
  },
})

// Assign the admin role (which includes the meta-permissions) to a user
// so they can manage permissions at runtime.
```

## Full Example

```ts
// 1. Set up auth with both plugins
import { betterAuth } from 'better-auth'
import { multiTenancy } from '@four-leaves/better-auth-multi-tenancy'
import {
  rbac,
  hasPermission,
} from '@four-leaves/better-auth-multi-tenancy-rbac'

export const auth = betterAuth({
  plugins: [multiTenancy(), rbac()],
})

// 2. Seed permissions in your database migration (not via the API)
//    INSERT INTO permission (name, resource, action) VALUES
//      ('invoice:read',   'invoice', 'read'),
//      ('invoice:write',  'invoice', 'write'),
//      ('invoice:delete', 'invoice', 'delete');

// 3. Create a tenant role
const { data: roleData } = await authClient.rbac.createTenantRole({
  params: { tenantId },
  body: {
    name: 'Billing Manager',
    permissionIds: [readId, writeId],
  },
})

// 4. Assign the role to a tenant member
await authClient.rbac.assignRole({
  params: { tenantId, memberId },
  body: { tenantRoleId: roleData.role.id },
})

// 5. Check permissions in a custom endpoint
const allowed = await hasPermission(ctx, tenantId, userId, 'invoice:write')
```

## Database Schema

The plugin creates four tables:

| Table                  | Description                                                 |
| ---------------------- | ----------------------------------------------------------- |
| `permission`           | Global permissions identified by name, resource, and action |
| `tenantRole`           | Roles scoped to a specific tenant                           |
| `tenantRolePermission` | Links tenant roles to their permissions                     |
| `tenantMemberRole`     | Assigns tenant roles to tenant members                      |

Table names can be overridden via the `schema` option (see [Plugin Options](#plugin-options)).

## License

MIT — see [LICENSE](./LICENSE).
