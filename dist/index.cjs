'use strict';

var api = require('better-auth/api');
var zod = require('zod');

// src/schemas/permission.ts
var permissionSchema = {
  fields: {
    name: {
      type: "string",
      required: true,
      unique: true
    },
    description: {
      type: "string",
      required: false
    },
    resource: {
      type: "string",
      required: true
    },
    action: {
      type: "string",
      required: true
    },
    createdAt: {
      type: "date",
      required: true
    },
    updatedAt: {
      type: "date",
      required: true
    }
  }
};

// src/schemas/tenant-role.ts
var tenantRoleSchema = {
  fields: {
    name: {
      type: "string",
      required: true
    },
    description: {
      type: "string",
      required: false
    },
    tenantId: {
      type: "string",
      required: true,
      references: {
        model: "tenant",
        field: "id",
        onDelete: "cascade"
      }
    },
    createdAt: {
      type: "date",
      required: true
    },
    updatedAt: {
      type: "date",
      required: true
    }
  }
};

// src/schemas/tenant-role-permission.ts
var tenantRolePermissionSchema = {
  fields: {
    tenantRoleId: {
      type: "string",
      required: true,
      references: {
        model: "tenantRole",
        field: "id",
        onDelete: "cascade"
      }
    },
    permissionId: {
      type: "string",
      required: true,
      references: {
        model: "permission",
        field: "id",
        onDelete: "cascade"
      }
    },
    createdAt: {
      type: "date",
      required: true
    }
  }
};

// src/schemas/tenant-member-role.ts
var tenantMemberRoleSchema = {
  fields: {
    tenantId: {
      type: "string",
      required: true,
      references: {
        model: "tenant",
        field: "id",
        onDelete: "cascade"
      }
    },
    tenantMemberId: {
      type: "string",
      required: true,
      references: {
        model: "tenantMember",
        field: "id",
        onDelete: "cascade"
      }
    },
    tenantRoleId: {
      type: "string",
      required: true,
      references: {
        model: "tenantRole",
        field: "id",
        onDelete: "cascade"
      }
    },
    createdAt: {
      type: "date",
      required: true
    },
    updatedAt: {
      type: "date",
      required: true
    }
  }
};
async function getUserPermissions(ctx, tenantId, userId) {
  const member = await ctx.context.adapter.findOne({
    model: "tenantMember",
    where: [
      { field: "tenantId", value: tenantId },
      { field: "userId", value: userId }
    ]
  });
  if (!member) return /* @__PURE__ */ new Set();
  const assignments = await ctx.context.adapter.findMany({
    model: "tenantMemberRole",
    where: [{ field: "tenantMemberId", value: member.id }]
  });
  if (assignments.length === 0) return /* @__PURE__ */ new Set();
  const rolePermissionSets = await Promise.all(
    assignments.map(
      (a) => ctx.context.adapter.findMany({
        model: "tenantRolePermission",
        where: [{ field: "tenantRoleId", value: a.tenantRoleId }]
      })
    )
  );
  const permissionIds = [
    ...new Set(rolePermissionSets.flat().map((rp) => rp.permissionId))
  ];
  if (permissionIds.length === 0) return /* @__PURE__ */ new Set();
  const permissions = await Promise.all(
    permissionIds.map(
      (id) => ctx.context.adapter.findOne({
        model: "permission",
        where: [{ field: "id", value: id }]
      })
    )
  );
  const names = /* @__PURE__ */ new Set();
  for (const p of permissions) {
    if (p) names.add(p.name);
  }
  return names;
}
async function requireCustomPermission(ctx, tenantId, userId, ref) {
  const matches = await ctx.context.adapter.findMany({
    model: "permission",
    where: [
      { field: "resource", value: ref.resource },
      { field: "action", value: ref.action }
    ]
  });
  const perm = matches[0];
  if (!perm) {
    throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
  }
  const allowed = await hasPermission(ctx, tenantId, userId, perm.name);
  if (!allowed) {
    throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
  }
}
async function requireGlobalPermission(ctx, userId, ref) {
  const matches = await ctx.context.adapter.findMany({
    model: "permission",
    where: [
      { field: "resource", value: ref.resource },
      { field: "action", value: ref.action }
    ]
  });
  const perm = matches[0];
  if (!perm) {
    throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
  }
  const memberships = await ctx.context.adapter.findMany({
    model: "tenantMember",
    where: [{ field: "userId", value: userId }]
  });
  for (const membership of memberships) {
    const assignments = await ctx.context.adapter.findMany({
      model: "tenantMemberRole",
      where: [{ field: "tenantMemberId", value: membership.id }]
    });
    for (const assignment of assignments) {
      const rolePerms = await ctx.context.adapter.findMany({
        model: "tenantRolePermission",
        where: [
          { field: "tenantRoleId", value: assignment.tenantRoleId },
          { field: "permissionId", value: perm.id }
        ]
      });
      if (rolePerms.length > 0) return;
    }
  }
  throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
}
async function hasPermission(ctx, tenantId, userId, permission) {
  const perms = await getUserPermissions(ctx, tenantId, userId);
  return perms.has(permission);
}
async function hasAnyOnePermission(ctx, tenantId, userId, permissions) {
  const perms = await getUserPermissions(ctx, tenantId, userId);
  return permissions.some((p) => perms.has(p));
}
async function hasAllPermissions(ctx, tenantId, userId, permissions) {
  const perms = await getUserPermissions(ctx, tenantId, userId);
  return permissions.every((p) => perms.has(p));
}

// src/endpoints/permissions.ts
var createPermission = (options) => api.createAuthEndpoint(
  "/rbac/permissions",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      name: zod.z.string().min(1),
      resource: zod.z.string().min(1),
      action: zod.z.string().min(1),
      description: zod.z.string().optional()
    })
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const createRef = options.authorization?.permissions?.create;
    if (!createRef) {
      throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
    }
    await requireGlobalPermission(ctx, user.id, createRef);
    const { name, resource, action, description } = ctx.body;
    const existingByName = await ctx.context.adapter.findOne({
      model: "permission",
      where: [{ field: "name", value: name }]
    });
    if (existingByName) {
      throw new api.APIError("CONFLICT", {
        message: "A permission with this name already exists."
      });
    }
    const existingByResourceAction = await ctx.context.adapter.findMany({
      model: "permission",
      where: [
        { field: "resource", value: resource },
        { field: "action", value: action }
      ]
    });
    if (existingByResourceAction.length > 0) {
      throw new api.APIError("CONFLICT", {
        message: "A permission with this resource and action already exists."
      });
    }
    const now = /* @__PURE__ */ new Date();
    const permission = await ctx.context.adapter.create({
      model: "permission",
      data: {
        name,
        resource,
        action,
        ...description !== void 0 && { description },
        createdAt: now,
        updatedAt: now
      }
    });
    await options.onPermissionCreated?.(permission);
    return ctx.json({ permission });
  }
);
var listPermissions = () => api.createAuthEndpoint(
  "/rbac/permissions",
  {
    method: "GET",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const permissions = await ctx.context.adapter.findMany({
      model: "permission"
    });
    return ctx.json({ permissions });
  }
);
var getPermission = () => api.createAuthEndpoint(
  "/rbac/permissions/:permissionId",
  {
    method: "GET",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { permissionId } = ctx.params;
    const permission = await ctx.context.adapter.findOne({
      model: "permission",
      where: [{ field: "id", value: permissionId }]
    });
    if (!permission) {
      throw new api.APIError("NOT_FOUND", { message: "Permission not found." });
    }
    return ctx.json({ permission });
  }
);
var updatePermission = (options) => api.createAuthEndpoint(
  "/rbac/permissions/:permissionId",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      name: zod.z.string().min(1).optional(),
      resource: zod.z.string().min(1).optional(),
      action: zod.z.string().min(1).optional(),
      description: zod.z.string().optional()
    })
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const updateRef = options.authorization?.permissions?.update;
    if (!updateRef) {
      throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
    }
    await requireGlobalPermission(ctx, user.id, updateRef);
    const { permissionId } = ctx.params;
    const { name, resource, action, description } = ctx.body;
    const existing = await ctx.context.adapter.findOne({
      model: "permission",
      where: [{ field: "id", value: permissionId }]
    });
    if (!existing) {
      throw new api.APIError("NOT_FOUND", { message: "Permission not found." });
    }
    if (name !== void 0 && name !== existing.name) {
      const conflict = await ctx.context.adapter.findOne({
        model: "permission",
        where: [{ field: "name", value: name }]
      });
      if (conflict) {
        throw new api.APIError("CONFLICT", {
          message: "A permission with this name already exists."
        });
      }
    }
    const effectiveResource = resource ?? existing.resource;
    const effectiveAction = action ?? existing.action;
    if (effectiveResource !== existing.resource || effectiveAction !== existing.action) {
      const conflicts = await ctx.context.adapter.findMany({
        model: "permission",
        where: [
          { field: "resource", value: effectiveResource },
          { field: "action", value: effectiveAction }
        ]
      });
      const otherConflict = conflicts.find((p) => p.id !== permissionId);
      if (otherConflict) {
        throw new api.APIError("CONFLICT", {
          message: "A permission with this resource and action already exists."
        });
      }
    }
    const now = /* @__PURE__ */ new Date();
    const permission = await ctx.context.adapter.update({
      model: "permission",
      where: [{ field: "id", value: permissionId }],
      update: {
        ...name !== void 0 && { name },
        ...resource !== void 0 && { resource },
        ...action !== void 0 && { action },
        ...description !== void 0 && { description },
        updatedAt: now
      }
    });
    if (permission) {
      await options.onPermissionUpdated?.(permission);
    }
    return ctx.json({ permission });
  }
);
var deletePermission = (options) => api.createAuthEndpoint(
  "/rbac/permissions/:permissionId/delete",
  {
    method: "POST",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const deleteRef = options.authorization?.permissions?.delete;
    if (!deleteRef) {
      throw new api.APIError("FORBIDDEN", { message: "Insufficient permissions." });
    }
    await requireGlobalPermission(ctx, user.id, deleteRef);
    const { permissionId } = ctx.params;
    const permission = await ctx.context.adapter.findOne({
      model: "permission",
      where: [{ field: "id", value: permissionId }]
    });
    if (!permission) {
      throw new api.APIError("NOT_FOUND", { message: "Permission not found." });
    }
    const junctionRows = await ctx.context.adapter.findMany({
      model: "tenantRolePermission",
      where: [{ field: "permissionId", value: permissionId }]
    });
    await Promise.all(
      junctionRows.map(
        (row) => ctx.context.adapter.delete({
          model: "tenantRolePermission",
          where: [{ field: "id", value: row.id }]
        })
      )
    );
    await ctx.context.adapter.delete({
      model: "permission",
      where: [{ field: "id", value: permissionId }]
    });
    await options.onPermissionDeleted?.(permission);
    return ctx.json({ success: true });
  }
);
async function requireTenantMember(ctx, tenantId, userId) {
  const member = await ctx.context.adapter.findOne({
    model: "tenantMember",
    where: [
      { field: "tenantId", value: tenantId },
      { field: "userId", value: userId }
    ]
  });
  if (!member) {
    throw new api.APIError("FORBIDDEN", {
      message: "You are not a member of this tenant."
    });
  }
  return member;
}
async function requireTenantOwner(ctx, tenantId, userId) {
  const tenant = await ctx.context.adapter.findOne({
    model: "tenant",
    where: [{ field: "id", value: tenantId }]
  });
  if (!tenant) {
    throw new api.APIError("NOT_FOUND", { message: "Tenant not found." });
  }
  if (tenant.ownerId !== userId) {
    throw new api.APIError("FORBIDDEN", {
      message: "Only the tenant owner can perform this action."
    });
  }
  return tenant;
}
var createTenantRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/roles",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      name: zod.z.string().min(1),
      description: zod.z.string().optional(),
      permissionIds: zod.z.array(zod.z.string()).optional()
    })
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId } = ctx.params;
    const { name, description, permissionIds } = ctx.body;
    const manageRef = options.authorization?.tenantRoles?.manage;
    if (manageRef) {
      await requireCustomPermission(ctx, tenantId, user.id, manageRef);
    } else {
      await requireTenantOwner(ctx, tenantId, user.id);
    }
    const existingRoles = await ctx.context.adapter.findMany({
      model: "tenantRole",
      where: [
        { field: "tenantId", value: tenantId },
        { field: "name", value: name }
      ]
    });
    if (existingRoles.length > 0) {
      throw new api.APIError("CONFLICT", {
        message: "A role with this name already exists in this tenant."
      });
    }
    const resolvedPermissions = [];
    if (permissionIds && permissionIds.length > 0) {
      for (const permId of permissionIds) {
        const perm = await ctx.context.adapter.findOne({
          model: "permission",
          where: [{ field: "id", value: permId }]
        });
        if (!perm) {
          throw new api.APIError("BAD_REQUEST", {
            message: `Permission with id "${permId}" not found.`
          });
        }
        resolvedPermissions.push(perm);
      }
    }
    const now = /* @__PURE__ */ new Date();
    const role = await ctx.context.adapter.create({
      model: "tenantRole",
      data: {
        name,
        ...description !== void 0 && { description },
        tenantId,
        createdAt: now,
        updatedAt: now
      }
    });
    const assignedPermissionIds = [];
    if (resolvedPermissions.length > 0) {
      await Promise.all(
        resolvedPermissions.map(async (perm) => {
          await ctx.context.adapter.create({
            model: "tenantRolePermission",
            data: {
              tenantRoleId: role.id,
              permissionId: perm.id,
              createdAt: now
            }
          });
          assignedPermissionIds.push(perm.id);
        })
      );
    }
    await options.onRoleCreated?.(role);
    return ctx.json({ role, permissionIds: assignedPermissionIds });
  }
);
var listTenantRoles = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/roles",
  {
    method: "GET",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId } = ctx.params;
    const viewRef = options.authorization?.tenantRoles?.view;
    if (viewRef) {
      await requireCustomPermission(ctx, tenantId, user.id, viewRef);
    } else {
      await requireTenantMember(ctx, tenantId, user.id);
    }
    const roles = await ctx.context.adapter.findMany({
      model: "tenantRole",
      where: [{ field: "tenantId", value: tenantId }]
    });
    return ctx.json({ roles });
  }
);
var getTenantRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/roles/:roleId",
  {
    method: "GET",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, roleId } = ctx.params;
    const viewRef = options.authorization?.tenantRoles?.view;
    if (viewRef) {
      await requireCustomPermission(ctx, tenantId, user.id, viewRef);
    } else {
      await requireTenantMember(ctx, tenantId, user.id);
    }
    const role = await ctx.context.adapter.findOne({
      model: "tenantRole",
      where: [{ field: "id", value: roleId }]
    });
    if (!role || role.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Role not found." });
    }
    const junctionRows = await ctx.context.adapter.findMany({
      model: "tenantRolePermission",
      where: [{ field: "tenantRoleId", value: roleId }]
    });
    return ctx.json({
      role,
      permissionIds: junctionRows.map((r) => r.permissionId)
    });
  }
);
var updateTenantRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/roles/:roleId",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      name: zod.z.string().min(1).optional(),
      description: zod.z.string().optional(),
      permissionIds: zod.z.array(zod.z.string()).optional()
    })
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, roleId } = ctx.params;
    const { name, description, permissionIds } = ctx.body;
    const manageRef = options.authorization?.tenantRoles?.manage;
    if (manageRef) {
      await requireCustomPermission(ctx, tenantId, user.id, manageRef);
    } else {
      await requireTenantOwner(ctx, tenantId, user.id);
    }
    const role = await ctx.context.adapter.findOne({
      model: "tenantRole",
      where: [{ field: "id", value: roleId }]
    });
    if (!role || role.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Role not found." });
    }
    if (name !== void 0 && name !== role.name) {
      const conflicts = await ctx.context.adapter.findMany({
        model: "tenantRole",
        where: [
          { field: "tenantId", value: tenantId },
          { field: "name", value: name }
        ]
      });
      if (conflicts.some((r) => r.id !== roleId)) {
        throw new api.APIError("CONFLICT", {
          message: "A role with this name already exists in this tenant."
        });
      }
    }
    const resolvedPermissions = [];
    if (permissionIds !== void 0) {
      for (const permId of permissionIds) {
        const perm = await ctx.context.adapter.findOne({
          model: "permission",
          where: [{ field: "id", value: permId }]
        });
        if (!perm) {
          throw new api.APIError("BAD_REQUEST", {
            message: `Permission with id "${permId}" not found.`
          });
        }
        resolvedPermissions.push(perm);
      }
    }
    const now = /* @__PURE__ */ new Date();
    const updatedRole = await ctx.context.adapter.update({
      model: "tenantRole",
      where: [{ field: "id", value: roleId }],
      update: {
        ...name !== void 0 && { name },
        ...description !== void 0 && { description },
        updatedAt: now
      }
    });
    let finalPermissionIds = [];
    if (permissionIds !== void 0) {
      const existing = await ctx.context.adapter.findMany({
        model: "tenantRolePermission",
        where: [{ field: "tenantRoleId", value: roleId }]
      });
      await Promise.all(
        existing.map(
          (row) => ctx.context.adapter.delete({
            model: "tenantRolePermission",
            where: [{ field: "id", value: row.id }]
          })
        )
      );
      await Promise.all(
        resolvedPermissions.map(async (perm) => {
          await ctx.context.adapter.create({
            model: "tenantRolePermission",
            data: {
              tenantRoleId: roleId,
              permissionId: perm.id,
              createdAt: now
            }
          });
        })
      );
      finalPermissionIds = resolvedPermissions.map((p) => p.id);
    } else {
      const current = await ctx.context.adapter.findMany({
        model: "tenantRolePermission",
        where: [{ field: "tenantRoleId", value: roleId }]
      });
      finalPermissionIds = current.map((r) => r.permissionId);
    }
    if (updatedRole) {
      await options.onRoleUpdated?.(updatedRole);
    }
    return ctx.json({ role: updatedRole, permissionIds: finalPermissionIds });
  }
);
var deleteTenantRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/roles/:roleId/delete",
  {
    method: "POST",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, roleId } = ctx.params;
    const manageRef = options.authorization?.tenantRoles?.manage;
    if (manageRef) {
      await requireCustomPermission(ctx, tenantId, user.id, manageRef);
    } else {
      await requireTenantOwner(ctx, tenantId, user.id);
    }
    const role = await ctx.context.adapter.findOne({
      model: "tenantRole",
      where: [{ field: "id", value: roleId }]
    });
    if (!role || role.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Role not found." });
    }
    const junctionRows = await ctx.context.adapter.findMany({
      model: "tenantRolePermission",
      where: [{ field: "tenantRoleId", value: roleId }]
    });
    await Promise.all(
      junctionRows.map(
        (row) => ctx.context.adapter.delete({
          model: "tenantRolePermission",
          where: [{ field: "id", value: row.id }]
        })
      )
    );
    const memberRoleRows = await ctx.context.adapter.findMany({
      model: "tenantMemberRole",
      where: [{ field: "tenantRoleId", value: roleId }]
    });
    await Promise.all(
      memberRoleRows.map(
        (row) => ctx.context.adapter.delete({
          model: "tenantMemberRole",
          where: [{ field: "id", value: row.id }]
        })
      )
    );
    await ctx.context.adapter.delete({
      model: "tenantRole",
      where: [{ field: "id", value: roleId }]
    });
    await options.onRoleDeleted?.(role);
    return ctx.json({ success: true });
  }
);
var assignRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/members/:memberId/roles",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      tenantRoleId: zod.z.string()
    })
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, memberId } = ctx.params;
    const { tenantRoleId } = ctx.body;
    const manageRef = options.authorization?.tenantMemberRoles?.manage;
    if (manageRef) {
      await requireCustomPermission(ctx, tenantId, user.id, manageRef);
    } else {
      await requireTenantOwner(ctx, tenantId, user.id);
    }
    const member = await ctx.context.adapter.findOne({
      model: "tenantMember",
      where: [{ field: "id", value: memberId }]
    });
    if (!member || member.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Member not found." });
    }
    const role = await ctx.context.adapter.findOne({
      model: "tenantRole",
      where: [{ field: "id", value: tenantRoleId }]
    });
    if (!role || role.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", {
        message: "Role not found in this tenant."
      });
    }
    const existing = await ctx.context.adapter.findMany({
      model: "tenantMemberRole",
      where: [
        { field: "tenantMemberId", value: memberId },
        { field: "tenantRoleId", value: tenantRoleId }
      ]
    });
    if (existing.length > 0) {
      throw new api.APIError("CONFLICT", {
        message: "This role is already assigned to this member."
      });
    }
    const now = /* @__PURE__ */ new Date();
    const assignment = await ctx.context.adapter.create({
      model: "tenantMemberRole",
      data: {
        tenantId,
        tenantMemberId: memberId,
        tenantRoleId,
        createdAt: now,
        updatedAt: now
      }
    });
    await options.onRoleAssigned?.(assignment);
    return ctx.json({ assignment });
  }
);
var listMemberRoles = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/members/:memberId/roles",
  {
    method: "GET",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, memberId } = ctx.params;
    const viewRef = options.authorization?.tenantMemberRoles?.view;
    if (viewRef) {
      await requireCustomPermission(ctx, tenantId, user.id, viewRef);
    } else {
      await requireTenantMember(ctx, tenantId, user.id);
    }
    const member = await ctx.context.adapter.findOne({
      model: "tenantMember",
      where: [{ field: "id", value: memberId }]
    });
    if (!member || member.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Member not found." });
    }
    const assignments = await ctx.context.adapter.findMany({
      model: "tenantMemberRole",
      where: [{ field: "tenantMemberId", value: memberId }]
    });
    return ctx.json({ assignments });
  }
);
var removeRole = (options) => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove",
  {
    method: "POST",
    use: [api.sessionMiddleware]
  },
  async (ctx) => {
    const { user } = ctx.context.session;
    const { tenantId, memberId, assignmentId } = ctx.params;
    const manageRef = options.authorization?.tenantMemberRoles?.manage;
    if (manageRef) {
      await requireCustomPermission(ctx, tenantId, user.id, manageRef);
    } else {
      await requireTenantOwner(ctx, tenantId, user.id);
    }
    const assignment = await ctx.context.adapter.findOne({
      model: "tenantMemberRole",
      where: [{ field: "id", value: assignmentId }]
    });
    if (!assignment || assignment.tenantMemberId !== memberId || assignment.tenantId !== tenantId) {
      throw new api.APIError("NOT_FOUND", { message: "Role assignment not found." });
    }
    await ctx.context.adapter.delete({
      model: "tenantMemberRole",
      where: [{ field: "id", value: assignmentId }]
    });
    await options.onRoleUnassigned?.(assignment);
    return ctx.json({ success: true });
  }
);
var checkPermission = () => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/permissions/check",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      permission: zod.z.string().min(1)
    })
  },
  async (ctx) => {
    const { tenantId } = ctx.params;
    const { permission } = ctx.body;
    const { user } = ctx.context.session;
    const result = await hasPermission(ctx, tenantId, user.id, permission);
    return ctx.json({ result });
  }
);
var checkAnyPermission = () => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/permissions/check-any",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      permissions: zod.z.array(zod.z.string().min(1)).min(1)
    })
  },
  async (ctx) => {
    const { tenantId } = ctx.params;
    const { permissions } = ctx.body;
    const { user } = ctx.context.session;
    const result = await hasAnyOnePermission(ctx, tenantId, user.id, permissions);
    return ctx.json({ result });
  }
);
var checkAllPermissions = () => api.createAuthEndpoint(
  "/rbac/tenants/:tenantId/permissions/check-all",
  {
    method: "POST",
    use: [api.sessionMiddleware],
    body: zod.z.object({
      permissions: zod.z.array(zod.z.string().min(1)).min(1)
    })
  },
  async (ctx) => {
    const { tenantId } = ctx.params;
    const { permissions } = ctx.body;
    const { user } = ctx.context.session;
    const result = await hasAllPermissions(ctx, tenantId, user.id, permissions);
    return ctx.json({ result });
  }
);

// src/plugin.ts
var rbac = (options = {}) => {
  const s = options.schema;
  const schema = {
    permission: {
      ...s?.permission?.modelName !== void 0 && { modelName: s.permission.modelName },
      fields: permissionSchema.fields
    },
    tenantRole: {
      ...s?.tenantRole?.modelName !== void 0 && { modelName: s.tenantRole.modelName },
      fields: tenantRoleSchema.fields
    },
    tenantRolePermission: {
      ...s?.tenantRolePermission?.modelName !== void 0 && { modelName: s.tenantRolePermission.modelName },
      fields: tenantRolePermissionSchema.fields
    },
    tenantMemberRole: {
      ...s?.tenantMemberRole?.modelName !== void 0 && { modelName: s.tenantMemberRole.modelName },
      fields: tenantMemberRoleSchema.fields
    }
  };
  return {
    id: "rbac",
    schema,
    endpoints: {
      // Global permissions
      createPermission: createPermission(options),
      listPermissions: listPermissions(),
      getPermission: getPermission(),
      updatePermission: updatePermission(options),
      deletePermission: deletePermission(options),
      // Tenant roles
      createTenantRole: createTenantRole(options),
      listTenantRoles: listTenantRoles(options),
      getTenantRole: getTenantRole(options),
      updateTenantRole: updateTenantRole(options),
      deleteTenantRole: deleteTenantRole(options),
      // Member role assignments
      assignRole: assignRole(options),
      listMemberRoles: listMemberRoles(options),
      removeRole: removeRole(options),
      // Client-side permission checks
      checkPermission: checkPermission(),
      checkAnyPermission: checkAnyPermission(),
      checkAllPermissions: checkAllPermissions()
    }
  };
};

exports.hasAllPermissions = hasAllPermissions;
exports.hasAnyOnePermission = hasAnyOnePermission;
exports.hasPermission = hasPermission;
exports.rbac = rbac;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map