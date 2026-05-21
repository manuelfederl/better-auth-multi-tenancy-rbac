'use strict';

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

exports.rbacClient = rbacClient;
//# sourceMappingURL=client.cjs.map
//# sourceMappingURL=client.cjs.map