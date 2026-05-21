export const permissionSchema = {
  fields: {
    name: {
      type: 'string' as const,
      required: true,
      unique: true,
    },
    description: {
      type: 'string' as const,
      required: false,
    },
    resource: {
      type: 'string' as const,
      required: true,
    },
    action: {
      type: 'string' as const,
      required: true,
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
