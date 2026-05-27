export const permissionSchema = {
  fields: {
    name: {
      type: 'string',
      required: true,
      unique: true,
    },
    description: {
      type: 'string',
      required: false,
    },
    resource: {
      type: 'string',
      required: true,
    },
    action: {
      type: 'string',
      required: true,
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
