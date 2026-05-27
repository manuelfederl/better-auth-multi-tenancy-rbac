export const tenantRoleSchema = {
  fields: {
    name: {
      type: 'string',
      required: true,
    },
    description: {
      type: 'string',
      required: false,
    },
    tenantId: {
      type: 'string',
      required: true,
      references: {
        model: 'tenant',
        field: 'id',
        onDelete: 'cascade',
      },
    },
    createdAt: {
      type: 'date',
      required: true,
    },
    updatedAt: {
      type: 'date',
      required: true,
    },
  },
} as const
