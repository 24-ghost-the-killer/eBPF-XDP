// The permission catalog the admin pages render (pages, actions, areas, presets).
import { PAGES, ACTIONS, AREAS, PRESETS, ADMIN_PAGE } from './authz'
export const permissionCatalog = () => ({
  pages: PAGES.map(({ id, label, hint }) => ({ id, label, hint })),
  actions: ACTIONS,
  areas: AREAS,
  presets: PRESETS,
  adminPage: ADMIN_PAGE,
})
