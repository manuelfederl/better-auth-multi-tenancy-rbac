import * as zod_v4_core from 'zod/v4/core';
import * as zod from 'zod';
import * as better_auth from 'better-auth';

interface Permission {
    id: string;
    name: string;
    description?: string;
    resource: string;
    action: string;
    createdAt: Date;
    updatedAt: Date;
}

interface TenantMember {
    id: string;
    tenantId: string;
    userId: string;
}

interface TenantRole {
    id: string;
    name: string;
    description?: string;
    tenantId: string;
    createdAt: Date;
    updatedAt: Date;
}

interface TenantRolePermission {
    id: string;
    tenantRoleId: string;
    permissionId: string;
    createdAt: Date;
}

interface TenantMemberRole {
    id: string;
    tenantId: string;
    tenantMemberId: string;
    tenantRoleId: string;
    createdAt: Date;
    updatedAt: Date;
}

interface PermissionRef {
    resource: string;
    action: string;
}
interface RbacOptions {
    schema?: {
        permission?: {
            modelName?: string;
        };
        tenantRole?: {
            modelName?: string;
        };
        tenantRolePermission?: {
            modelName?: string;
        };
        tenantMemberRole?: {
            modelName?: string;
        };
    };
    /**
     * Override the default owner/member authorization checks for tenant-scoped
     * endpoints with a RBAC permission lookup. When set, the system finds the
     * permission matching the given (resource, action) pair and verifies the
     * calling user holds it in the tenant. Falls back to the built-in owner or
     * member check when omitted.
     */
    authorization?: {
        /**
         * Guards the global permission write endpoints (createPermission, updatePermission,
         * deletePermission). When omitted these endpoints are **disabled** and return
         * FORBIDDEN — permissions must be seeded via the database instead.
         */
        permissions?: {
            /** Required to call createPermission. */
            create?: PermissionRef;
            /** Required to call updatePermission. */
            update?: PermissionRef;
            /** Required to call deletePermission. */
            delete?: PermissionRef;
        };
        tenantRoles?: {
            /** Guards listTenantRoles and getTenantRole. Default: tenant membership. */
            view?: PermissionRef;
            /** Guards createTenantRole, updateTenantRole, deleteTenantRole. Default: tenant ownership. */
            manage?: PermissionRef;
        };
        tenantMemberRoles?: {
            /** Guards listMemberRoles. Default: tenant membership. */
            view?: PermissionRef;
            /** Guards assignRole and removeRole. Default: tenant ownership. */
            manage?: PermissionRef;
        };
    };
    onPermissionCreated?: (permission: Permission) => Promise<void> | void;
    onPermissionUpdated?: (permission: Permission) => Promise<void> | void;
    onPermissionDeleted?: (permission: Permission) => Promise<void> | void;
    onRoleCreated?: (role: TenantRole) => Promise<void> | void;
    onRoleUpdated?: (role: TenantRole) => Promise<void> | void;
    onRoleDeleted?: (role: TenantRole) => Promise<void> | void;
    onRoleAssigned?: (assignment: TenantMemberRole) => Promise<void> | void;
    onRoleUnassigned?: (assignment: TenantMemberRole) => Promise<void> | void;
}

/**
 * Better Auth plugin that adds role-based access control (RBAC) to a multi-tenant
 * application. Designed to be used alongside `better-auth-multi-tenancy`.
 *
 * Registers four database tables (`permission`, `tenantRole`, `tenantRolePermission`,
 * `tenantMemberRole`) and 16 API endpoints covering global permission management,
 * per-tenant role management, member role assignment, and client-side permission checks.
 *
 * Server-side utility functions (`hasPermission`, `hasAnyOnePermission`,
 * `hasAllPermissions`) are exported from the main entry point for use in
 * application code and custom endpoints.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { multiTenancy } from "better-auth-multi-tenancy";
 * import { rbac } from "better-auth-multi-tenancy-rbac";
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     multiTenancy(),
 *     rbac({
 *       schema: {
 *         permission: { modelName: "rbac_permission" },
 *         tenantRole: { modelName: "rbac_tenant_role" },
 *       },
 *       onPermissionCreated: async (permission) => {
 *         console.log(`Permission "${permission.name}" created`);
 *       },
 *       onRoleDeleted: async (role) => {
 *         console.log(`Role "${role.name}" deleted from tenant ${role.tenantId}`);
 *       },
 *       onRoleAssigned: async (assignment) => {
 *         console.log(`Role assigned to member ${assignment.tenantMemberId}`);
 *       },
 *     }),
 *   ],
 * });
 * ```
 */
declare const rbac: (options?: RbacOptions) => {
    id: "rbac";
    schema: {
        permission: {
            fields: {
                readonly name: {
                    readonly type: "string";
                    readonly required: true;
                    readonly unique: true;
                };
                readonly description: {
                    readonly type: "string";
                    readonly required: false;
                };
                readonly resource: {
                    readonly type: "string";
                    readonly required: true;
                };
                readonly action: {
                    readonly type: "string";
                    readonly required: true;
                };
                readonly createdAt: {
                    readonly type: "date";
                    readonly required: true;
                };
                readonly updatedAt: {
                    readonly type: "date";
                    readonly required: true;
                };
            };
            modelName?: string;
        };
        tenantRole: {
            fields: {
                readonly name: {
                    readonly type: "string";
                    readonly required: true;
                };
                readonly description: {
                    readonly type: "string";
                    readonly required: false;
                };
                readonly tenantId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "tenant";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly createdAt: {
                    readonly type: "date";
                    readonly required: true;
                };
                readonly updatedAt: {
                    readonly type: "date";
                    readonly required: true;
                };
            };
            modelName?: string;
        };
        tenantRolePermission: {
            fields: {
                readonly tenantRoleId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "tenantRole";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly permissionId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "permission";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly createdAt: {
                    readonly type: "date";
                    readonly required: true;
                };
            };
            modelName?: string;
        };
        tenantMemberRole: {
            fields: {
                readonly tenantId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "tenant";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly tenantMemberId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "tenantMember";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly tenantRoleId: {
                    readonly type: "string";
                    readonly required: true;
                    readonly references: {
                        readonly model: "tenantRole";
                        readonly field: "id";
                        readonly onDelete: "cascade";
                    };
                };
                readonly createdAt: {
                    readonly type: "date";
                    readonly required: true;
                };
                readonly updatedAt: {
                    readonly type: "date";
                    readonly required: true;
                };
            };
            modelName?: string;
        };
    };
    endpoints: {
        createPermission: better_auth.StrictEndpoint<"/rbac/permissions", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                name: zod.ZodString;
                resource: zod.ZodString;
                action: zod.ZodString;
                description: zod.ZodOptional<zod.ZodString>;
            }, zod_v4_core.$strip>;
        }, {
            permission: Permission;
        }>;
        listPermissions: better_auth.StrictEndpoint<"/rbac/permissions", {
            method: "GET";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            permissions: Permission[];
        }>;
        getPermission: better_auth.StrictEndpoint<"/rbac/permissions/:permissionId", {
            method: "GET";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            permission: Permission;
        }>;
        updatePermission: better_auth.StrictEndpoint<"/rbac/permissions/:permissionId", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                name: zod.ZodOptional<zod.ZodString>;
                resource: zod.ZodOptional<zod.ZodString>;
                action: zod.ZodOptional<zod.ZodString>;
                description: zod.ZodOptional<zod.ZodString>;
            }, zod_v4_core.$strip>;
        }, {
            permission: Permission | null;
        }>;
        deletePermission: better_auth.StrictEndpoint<"/rbac/permissions/:permissionId/delete", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            success: boolean;
        }>;
        createTenantRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/roles", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                name: zod.ZodString;
                description: zod.ZodOptional<zod.ZodString>;
                permissionIds: zod.ZodOptional<zod.ZodArray<zod.ZodString>>;
            }, zod_v4_core.$strip>;
        }, {
            role: TenantRole;
            permissionIds: string[];
        }>;
        listTenantRoles: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/roles", {
            method: "GET";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            roles: TenantRole[];
        }>;
        getTenantRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/roles/:roleId", {
            method: "GET";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            role: TenantRole;
            permissionIds: string[];
        }>;
        updateTenantRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/roles/:roleId", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                name: zod.ZodOptional<zod.ZodString>;
                description: zod.ZodOptional<zod.ZodString>;
                permissionIds: zod.ZodOptional<zod.ZodArray<zod.ZodString>>;
            }, zod_v4_core.$strip>;
        }, {
            role: TenantRole | null;
            permissionIds: string[];
        }>;
        deleteTenantRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/roles/:roleId/delete", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            success: boolean;
        }>;
        assignRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/members/:memberId/roles", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                tenantRoleId: zod.ZodString;
            }, zod_v4_core.$strip>;
        }, {
            assignment: TenantMemberRole;
        }>;
        listMemberRoles: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/members/:memberId/roles", {
            method: "GET";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            assignments: TenantMemberRole[];
        }>;
        removeRole: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
        }, {
            success: boolean;
        }>;
        checkPermission: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/permissions/check", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                permission: zod.ZodString;
            }, zod_v4_core.$strip>;
        }, {
            result: boolean;
        }>;
        checkAnyPermission: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/permissions/check-any", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                permissions: zod.ZodArray<zod.ZodString>;
            }, zod_v4_core.$strip>;
        }, {
            result: boolean;
        }>;
        checkAllPermissions: better_auth.StrictEndpoint<"/rbac/tenants/:tenantId/permissions/check-all", {
            method: "POST";
            use: ((inputContext: better_auth.MiddlewareInputContext<better_auth.MiddlewareOptions>) => Promise<{
                session: {
                    session: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        userId: string;
                        expiresAt: Date;
                        token: string;
                        ipAddress?: string | null | undefined;
                        userAgent?: string | null | undefined;
                    };
                    user: Record<string, any> & {
                        id: string;
                        createdAt: Date;
                        updatedAt: Date;
                        email: string;
                        emailVerified: boolean;
                        name: string;
                        image?: string | null | undefined;
                    };
                };
            }>)[];
            body: zod.ZodObject<{
                permissions: zod.ZodArray<zod.ZodString>;
            }, zod_v4_core.$strip>;
        }, {
            result: boolean;
        }>;
    };
};

/**
 * Returns true if the user has the specified permission in the given tenant.
 * A user's permissions are the union of all permissions from all their tenant roles.
 */
declare function hasPermission(ctx: any, tenantId: string, userId: string, permission: string): Promise<boolean>;
/**
 * Returns true if the user has at least one of the specified permissions in the given tenant.
 */
declare function hasAnyOnePermission(ctx: any, tenantId: string, userId: string, permissions: string[]): Promise<boolean>;
/**
 * Returns true if the user has every one of the specified permissions in the given tenant.
 */
declare function hasAllPermissions(ctx: any, tenantId: string, userId: string, permissions: string[]): Promise<boolean>;

export { type Permission, type PermissionRef, type RbacOptions, type TenantMember, type TenantMemberRole, type TenantRole, type TenantRolePermission, hasAllPermissions, hasAnyOnePermission, hasPermission, rbac };
