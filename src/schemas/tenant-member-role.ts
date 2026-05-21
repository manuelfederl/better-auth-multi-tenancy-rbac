export const tenantMemberRoleSchema = {
  fields: {
    tenantId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'tenant',
        field: 'id',
        onDelete: 'cascade' as const,
      },
    },
    tenantMemberId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'tenantMember',
        field: 'id',
        onDelete: 'cascade' as const,
      },
    },
    tenantRoleId: {
      type: 'string' as const,
      required: true,
      references: {
        model: 'tenantRole',
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
