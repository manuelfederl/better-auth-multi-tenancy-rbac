export const tenantRolePermissionSchema = {
  fields: {
    tenantRoleId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'tenantRole',
        field: 'id',
        onDelete: 'cascade' as const,
      },
    },
    permissionId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'permission',
        field: 'id',
        onDelete: 'cascade' as const,
      },
    },
    createdAt: {
      type: 'date' as const,
      required: true,
    },
  },
} as const
