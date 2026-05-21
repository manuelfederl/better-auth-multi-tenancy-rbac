# better-auth-multi-tenancy-rbac

A [Better Auth](https://better-auth.com) plugin that adds role-based access control (RBAC) to multi-tenant applications. Designed to work alongside [better-auth-multi-tenancy](https://github.com/flt/better-auth-multi-tenancy).

## Features

- **Permission management** — define global permissions with a resource/action model
- **Tenant roles** — create roles scoped to individual tenants and assign permissions to them
- **Member role assignments** — assign any number of roles to tenant members
- **Permission evaluation** — server-side utilities to check a user's effective permissions within a tenant, with deduplication across overlapping roles
- **Full type safety** — server and client plugins with TypeScript inference
- **Database agnostic** — works with any Better Auth adapter (SQLite, PostgreSQL, MySQL, …)

## Installation

```bash
npm install better-auth-multi-tenancy-rbac
```

`better-auth` is a peer dependency and must be installed separately.

## Setup

### 1. Server

Add the plugin to your Better Auth configuration alongside `better-auth-multi-tenancy`:

```ts
import { betterAuth } from "better-auth";
import { multiTenancy } from "better-auth-multi-tenancy";
import { rbac } from "better-auth-multi-tenancy-rbac";

export const auth = betterAuth({
  // ... your existing config
  plugins: [
    multiTenancy(),
    rbac({
      // Optional: react to role assignments
      onRoleAssigned: async (assignment) => {
        console.log(`Role ${assignment.tenantRoleId} assigned to member ${assignment.tenantMemberId}`);
      },
    }),
  ],
});
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
import { createAuthClient } from "better-auth/client";
import { rbacClient } from "better-auth-multi-tenancy-rbac/client";

export const authClient = createAuthClient({
  // ... your existing config
  plugins: [rbacClient()],
});
```

All methods are available under `authClient.rbac.*`.

## API Reference

### Permission Checks (Client-Side)

These endpoints let any client evaluate permissions without calling server-side utilities directly. All three default to the current session user when `userId` is omitted, which covers the common case of checking your own access.

| Method | HTTP | Path | Description |
|--------|------|------|-------------|
| `checkPermission` | POST | `/rbac/tenants/:tenantId/permissions/check` | Check a single permission |
| `checkAnyPermission` | POST | `/rbac/tenants/:tenantId/permissions/check-any` | Check if at least one permission matches |
| `checkAllPermissions` | POST | `/rbac/tenants/:tenantId/permissions/check-all` | Check if every permission matches |

All three return `{ result: boolean }`.

**Check a single permission**

```ts
const { data } = await authClient.rbac.checkPermission({
  params: { tenantId: "tenant-id" },
  body: { permission: "invoice:read" },
});

if (!data.result) {
  // user cannot read invoices
}
```

**Check if the user has at least one matching permission**

```ts
const { data } = await authClient.rbac.checkAnyPermission({
  params: { tenantId: "tenant-id" },
  body: { permissions: ["invoice:read", "invoice:write"] },
});
```

**Check if the user has all of the listed permissions**

```ts
const { data } = await authClient.rbac.checkAllPermissions({
  params: { tenantId: "tenant-id" },
  body: { permissions: ["invoice:read", "invoice:write", "invoice:delete"] },
});
```

**Check another user's permissions** (pass `userId` explicitly)

```ts
const { data } = await authClient.rbac.checkPermission({
  params: { tenantId: "tenant-id" },
  body: { permission: "invoice:read", userId: "other-user-id" },
});
```

### Permissions

Permissions are global — they are not scoped to a tenant. Each permission represents a specific capability identified by a `resource` and `action` pair (e.g. `resource: "invoice"`, `action: "read"`). The `name` field is a unique human-readable key (e.g. `"invoice:read"`) used when evaluating access.

| Method | HTTP | Path | Description |
|--------|------|------|-------------|
| `createPermission` | POST | `/rbac/permissions` | Create a new permission |
| `listPermissions` | GET | `/rbac/permissions` | List all permissions |
| `getPermission` | GET | `/rbac/permissions/:permissionId` | Get a permission by id |
| `updatePermission` | POST | `/rbac/permissions/:permissionId` | Update a permission |
| `deletePermission` | POST | `/rbac/permissions/:permissionId/delete` | Delete a permission |

**Create a permission**

```ts
const { data } = await authClient.rbac.createPermission({
  name: "invoice:read",
  resource: "invoice",
  action: "read",
  description: "View invoices", // optional
});
```

**List all permissions**

```ts
const { data } = await authClient.rbac.listPermissions();
```

### Tenant Roles

Roles are scoped to a tenant. A role groups one or more permissions together so they can be assigned to members as a unit. When a role is created or updated, the full set of permission IDs is supplied — updating `permissionIds` always replaces the existing set.

| Method | HTTP | Path | Description |
|--------|------|------|-------------|
| `createTenantRole` | POST | `/rbac/tenants/:tenantId/roles` | Create a role in a tenant (owner only) |
| `listTenantRoles` | GET | `/rbac/tenants/:tenantId/roles` | List all roles in a tenant |
| `getTenantRole` | GET | `/rbac/tenants/:tenantId/roles/:roleId` | Get a role and its permission IDs |
| `updateTenantRole` | POST | `/rbac/tenants/:tenantId/roles/:roleId` | Update a role (owner only) |
| `deleteTenantRole` | POST | `/rbac/tenants/:tenantId/roles/:roleId/delete` | Delete a role (owner only) |

**Create a role with permissions**

```ts
const { data } = await authClient.rbac.createTenantRole({
  params: { tenantId: "tenant-id" },
  body: {
    name: "Billing Manager",
    description: "Can manage invoices and payments",
    permissionIds: ["permission-id-1", "permission-id-2"],
  },
});
```

**Update a role's permissions (full replacement)**

```ts
await authClient.rbac.updateTenantRole({
  params: { tenantId: "tenant-id", roleId: "role-id" },
  body: {
    permissionIds: ["permission-id-1", "permission-id-3"],
  },
});
```

### Member Role Assignments

A tenant member can hold any number of roles. Their effective permissions are the union of all permissions from all their assigned roles — overlapping permissions across roles are automatically deduplicated during evaluation.

| Method | HTTP | Path | Description |
|--------|------|------|-------------|
| `assignRole` | POST | `/rbac/tenants/:tenantId/members/:memberId/roles` | Assign a role to a member (owner only) |
| `listMemberRoles` | GET | `/rbac/tenants/:tenantId/members/:memberId/roles` | List a member's role assignments |
| `removeRole` | POST | `/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove` | Remove a role assignment (owner only) |

**Assign a role to a member**

```ts
await authClient.rbac.assignRole({
  params: { tenantId: "tenant-id", memberId: "member-id" },
  body: { tenantRoleId: "role-id" },
});
```

**List a member's roles**

```ts
const { data } = await authClient.rbac.listMemberRoles({
  params: { tenantId: "tenant-id", memberId: "member-id" },
});
```

## Permission Evaluation

The three server-side utility functions let you gate any server logic behind a permission check. Import them from the main entry point and call them from your own endpoints or middleware, passing the Better Auth endpoint context (`ctx`).

```ts
import { hasPermission, hasAnyOnePermission, hasAllPermissions } from "better-auth-multi-tenancy-rbac";
```

A user's effective permissions are the union of all permissions granted by their tenant roles. Overlapping permissions across multiple roles are deduplicated automatically.

### `hasPermission`

Returns `true` if the user has the specified permission within the tenant.

```ts
const canRead = await hasPermission(ctx, tenantId, userId, "invoice:read");

if (!canRead) {
  throw new APIError("FORBIDDEN", { message: "You cannot view invoices." });
}
```

### `hasAnyOnePermission`

Returns `true` if the user has **at least one** of the specified permissions.

```ts
const canManage = await hasAnyOnePermission(ctx, tenantId, userId, [
  "invoice:read",
  "invoice:write",
]);
```

### `hasAllPermissions`

Returns `true` if the user has **every** permission in the list.

```ts
const isFullAdmin = await hasAllPermissions(ctx, tenantId, userId, [
  "invoice:read",
  "invoice:write",
  "invoice:delete",
]);
```

## Plugin Options

```ts
rbac({
  // Permission lifecycle
  onPermissionCreated: async (permission) => { ... },
  onPermissionUpdated: async (permission) => { ... },
  onPermissionDeleted: async (permission) => { ... },

  // Tenant role lifecycle
  onRoleCreated: async (role) => { ... },
  onRoleUpdated: async (role) => { ... },
  onRoleDeleted: async (role) => { ... },

  // Member role assignment lifecycle
  onRoleAssigned:   async (assignment) => { ... },
  onRoleUnassigned: async (assignment) => { ... },
})
```

All callbacks are optional and may be async. The deleted-entity callbacks receive the record as it existed immediately before deletion.

## Full Example

```ts
// 1. Set up auth with both plugins
import { betterAuth } from "better-auth";
import { multiTenancy } from "better-auth-multi-tenancy";
import { rbac, hasPermission } from "better-auth-multi-tenancy-rbac";

export const auth = betterAuth({
  plugins: [multiTenancy(), rbac()],
});

// 2. Define permissions (e.g. on app startup or via an admin endpoint)
await authClient.rbac.createPermission({ name: "invoice:read",   resource: "invoice", action: "read"   });
await authClient.rbac.createPermission({ name: "invoice:write",  resource: "invoice", action: "write"  });
await authClient.rbac.createPermission({ name: "invoice:delete", resource: "invoice", action: "delete" });

// 3. Create a tenant role
const { data: roleData } = await authClient.rbac.createTenantRole({
  params: { tenantId },
  body: {
    name: "Billing Manager",
    permissionIds: [readId, writeId],
  },
});

// 4. Assign the role to a tenant member
await authClient.rbac.assignRole({
  params: { tenantId, memberId },
  body: { tenantRoleId: roleData.role.id },
});

// 5. Check permissions in a custom endpoint
const allowed = await hasPermission(ctx, tenantId, userId, "invoice:write");
```

## Database Schema

The plugin creates four tables:

| Table | Description |
|-------|-------------|
| `permission` | Global permissions identified by name, resource, and action |
| `tenantRole` | Roles scoped to a specific tenant |
| `tenantRolePermission` | Links tenant roles to their permissions |
| `tenantMemberRole` | Assigns tenant roles to tenant members |

## License

MIT — see [LICENSE](./LICENSE).
