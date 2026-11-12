import { AdminPanel } from "../components/AdminPanel";
// Layout route for /admin/*: the individual pages are nested routes (see App.tsx).
export function AdminPage(){ return <AdminPanel ownerMode />; }
