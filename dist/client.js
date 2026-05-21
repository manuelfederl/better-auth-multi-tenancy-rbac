// src/client.ts
var rbacClient = () => {
  return {
    id: "rbac",
    $InferServerPlugin: {},
    pathMethods: {
      "/rbac/permissions": "POST",
      "/rbac/permissions/:permissionId": "POST",
      "/rbac/permissions/:permissionId/delete": "POST",
      "/rbac/tenants/:tenantId/roles": "POST",
      "/rbac/tenants/:tenantId/roles/:roleId": "POST",
      "/rbac/tenants/:tenantId/roles/:roleId/delete": "POST",
      "/rbac/tenants/:tenantId/members/:memberId/roles": "POST",
      "/rbac/tenants/:tenantId/members/:memberId/roles/:assignmentId/remove": "POST",
      "/rbac/tenants/:tenantId/permissions/check": "POST",
      "/rbac/tenants/:tenantId/permissions/check-any": "POST",
      "/rbac/tenants/:tenantId/permissions/check-all": "POST"
    }
  };
};

export { rbacClient };
//# sourceMappingURL=client.js.map
//# sourceMappingURL=client.js.map