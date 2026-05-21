import { permissionSchema } from './permission'
import { tenantRoleSchema } from './tenant-role'
import { tenantRolePermissionSchema } from './tenant-role-permission'
import { tenantMemberRoleSchema } from './tenant-member-role'

export {
  permissionSchema,
  tenantRoleSchema,
  tenantRolePermissionSchema,
  tenantMemberRoleSchema,
}

export const rbacSchema = {
  permission: permissionSchema,
  tenantRole: tenantRoleSchema,
  tenantRolePermission: tenantRolePermissionSchema,
  tenantMemberRole: tenantMemberRoleSchema,
} as const
