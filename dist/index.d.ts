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

interface RbacOptions {
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
        readonly permission: {
            readonly fields: {
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
        };
        readonly tenantRole: {
            readonly fields: {
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
        };
        readonly tenantRolePermission: {
            readonly fields: {
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
        };
        readonly tenantMemberRole: {
            readonly fields: {
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
            }, "strip", zod.ZodTypeAny, {
                name: string;
                resource: string;
                action: string;
                description?: string | undefined;
            }, {
                name: string;
                resource: string;
                action: string;
                description?: string | undefined;
            }>;
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
            }, "strip", zod.ZodTypeAny, {
                name?: string | undefined;
                resource?: string | undefined;
                action?: string | undefined;
                description?: string | undefined;
            }, {
                name?: string | undefined;
                resource?: string | undefined;
                action?: string | undefined;
                description?: string | undefined;
            }>;
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
                permissionIds: zod.ZodOptional<zod.ZodArray<zod.ZodString, "many">>;
            }, "strip", zod.ZodTypeAny, {
                name: string;
                description?: string | undefined;
                permissionIds?: string[] | undefined;
            }, {
                name: string;
                description?: string | undefined;
                permissionIds?: string[] | undefined;
            }>;
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
                permissionIds: zod.ZodOptional<zod.ZodArray<zod.ZodString, "many">>;
            }, "strip", zod.ZodTypeAny, {
                name?: string | undefined;
                description?: string | undefined;
                permissionIds?: string[] | undefined;
            }, {
                name?: string | undefined;
                description?: string | undefined;
                permissionIds?: string[] | undefined;
            }>;
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
            }, "strip", zod.ZodTypeAny, {
                tenantRoleId: string;
            }, {
                tenantRoleId: string;
            }>;
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
                userId: zod.ZodOptional<zod.ZodString>;
            }, "strip", zod.ZodTypeAny, {
                permission: string;
                userId?: string | undefined;
            }, {
                permission: string;
                userId?: string | undefined;
            }>;
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
                permissions: zod.ZodArray<zod.ZodString, "many">;
                userId: zod.ZodOptional<zod.ZodString>;
            }, "strip", zod.ZodTypeAny, {
                permissions: string[];
                userId?: string | undefined;
            }, {
                permissions: string[];
                userId?: string | undefined;
            }>;
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
                permissions: zod.ZodArray<zod.ZodString, "many">;
                userId: zod.ZodOptional<zod.ZodString>;
            }, "strip", zod.ZodTypeAny, {
                permissions: string[];
                userId?: string | undefined;
            }, {
                permissions: string[];
                userId?: string | undefined;
            }>;
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

export { type Permission, type RbacOptions, type TenantMemberRole, type TenantRole, type TenantRolePermission, hasAllPermissions, hasAnyOnePermission, hasPermission, rbac };
