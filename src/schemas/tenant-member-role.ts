export const tenantMemberRoleSchema = {
  fields: {
    tenantId: {
      type: 'string',
      required: true,
      references: {
        model: 'tenant',
        field: 'id',
        onDelete: 'cascade',
      },
    },
    tenantMemberId: {
      type: 'string',
      required: true,
      references: {
        model: 'tenantMember',
        field: 'id',
        onDelete: 'cascade',
      },
    },
    tenantRoleId: {
      type: 'string',
      required: true,
      references: {
        model: 'tenantRole',
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
