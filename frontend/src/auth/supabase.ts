export interface SupabaseSession { access_token:string; refresh_token:string; expires_in:number; expires_at?:number; token_type:string; user:{id:string;email?:string|null}; }
const URL=(import.meta.env.VITE_SUPABASE_URL as string|undefined)?.replace(/\/$/,"");
const ANON=import.meta.env.VITE_SUPABASE_ANON_KEY as string|undefined;
const KEY="mirsad_supabase_session";
// Supabase Auth هو مزوّد المصادقة الوحيد في هذا المشروع (لا يوجد مسار محلي
// بديل بعد الآن). إن لم يكن VITE_SUPABASE_URL/VITE_SUPABASE_ANON_KEY مضبوطَين
// فهذا خطأ إعداد يجب إصلاحه، وليس حالة يجب التعامل معها بمزوّد آخر.
if (!URL || !ANON) {
  // eslint-disable-next-line no-console
  console.error("VITE_SUPABASE_URL/VITE_SUPABASE_ANON_KEY غير مضبوطَين — المصادقة لن تعمل.");
}
const headers=()=>({apikey:ANON??"","Content-Type":"application/json"});
function save(s:SupabaseSession|null){try{s?sessionStorage.setItem(KEY,JSON.stringify(s)):sessionStorage.removeItem(KEY)}catch{}}
export function getSession():SupabaseSession|null{try{const raw=sessionStorage.getItem(KEY);return raw?JSON.parse(raw) as SupabaseSession:null}catch{return null}}
export function getAccessToken(){return getSession()?.access_token??""}
async function request(path:string,body:unknown){if(!URL||!ANON)throw new Error("Supabase is not configured");const r=await fetch(`${URL}/auth/v1${path}`,{method:"POST",headers:headers(),body:JSON.stringify(body)});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error_description??d.msg??d.message??"Supabase authentication failed");const s=d as SupabaseSession;if(s.access_token){s.expires_at=Math.floor(Date.now()/1000)+Number(s.expires_in??3600);save(s)}return s}
export function signIn(email:string,password:string){return request("/token?grant_type=password",{email,password})}
export async function signUp(email:string,password:string,tenantName:string){const s=await request("/signup",{email,password,data:{tenant_name:tenantName}});return s.access_token?s:null}
export async function refreshSession(){const s=getSession();if(!s?.refresh_token)return null;try{return await request("/token?grant_type=refresh_token",{refresh_token:s.refresh_token})}catch{save(null);return null}}
export async function signOut(){
  const s=getSession();
  try {
    if (URL && ANON && s?.access_token) {
      await fetch(`${URL}/auth/v1/logout`, {
        method:"POST",
        headers:{...headers(), Authorization:`Bearer ${s.access_token}`},
      });
    }
  } finally {
    save(null);
  }
}
export function shouldRefresh(s:SupabaseSession|null){return Boolean(s?.expires_at&&s.expires_at-Math.floor(Date.now()/1000)<60)}

export type AppRole = "viewer" | "analyst" | "admin" | "owner";
export function getRole(): AppRole {
  const token = getAccessToken();
  try {
    const encoded = token.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/");
    if (!encoded) return "viewer";
    const payload = JSON.parse(atob(encoded + "=".repeat((4 - encoded.length % 4) % 4))) as {
      app_metadata?: { role?: string };
      role?: string;
    };
    const role = String(payload.app_metadata?.role ?? payload.role ?? "viewer").toLowerCase();
    return ["viewer", "analyst", "admin", "owner"].includes(role) ? role as AppRole : "viewer";
  } catch {
    return "viewer";
  }
}
