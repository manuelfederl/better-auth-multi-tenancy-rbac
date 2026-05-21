export const tenantRoleSchema = {
  fields: {
    name: {
      type: 'string' as const,
      required: true,
    },
    description: {
      type: 'string' as const,
      required: false,
    },
    tenantId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'tenant',
        field: 'id',
        onDelete: 'cascade' as const,
      },
    },
    createdAt: {
      type: 'date' as const,
      required: true,
    },
    updatedAt: {
      type: 'date' as const,
      required: true,
    },
  },
} as const
