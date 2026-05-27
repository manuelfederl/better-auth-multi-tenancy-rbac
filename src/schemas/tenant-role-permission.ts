export const tenantRolePermissionSchema = {
  fields: {
    tenantRoleId: {
      type: 'string',
      required: true,
      references: {
        model: 'tenantRole',
        field: 'id',
        onDelete: 'cascade',
      },
    },
    permissionId: {
      type: 'string',
      required: true,
      references: {
        model: 'permission',
        field: 'id',
        onDelete: 'cascade',
      },
    },
    createdAt: {
      type: 'date',
      required: true,
    },
  },
} as const
