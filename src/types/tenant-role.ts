export interface TenantRole {
  id: string
  name: string
  description?: string
  tenantId: string
  createdAt: Date
  updatedAt: Date
}
