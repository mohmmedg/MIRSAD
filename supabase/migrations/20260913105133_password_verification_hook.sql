-- Password Verification Hook — لقفل الحساب بعد محاولات دخول فاشلة
-- متكررة (max_failed_logins بجدول admin_settings.security_policy).
--
-- هذا الـ hook يُسجَّل داخل GoTrue نفسه (Authentication → Hooks →
-- "Password Verification Attempt" بلوحة تحكم Supabase) ويُستدعى مع كل
-- محاولة دخول بكلمة مرور، قبل إصدار أي توكن. تسجيل الدخول يمر بالكامل عبر
-- Supabase مباشرة من الواجهة ولا يمر إطلاقاً عبر الـ backend، لذلك منطق
-- القفل لا يمكن أن يعيش في Python — يجب أن يعيش هنا.
--
-- ⚠️ خطوة يدوية مطلوبة بعد هذا: فعّلها من Authentication → Hooks →
-- Password Verification Attempt → اختر public.hook_password_verification_attempt.

create table if not exists public.auth_failed_login_attempts (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  attempted_at timestamptz not null default now()
);
create index if not exists auth_failed_login_attempts_user_idx
  on public.auth_failed_login_attempts(user_id, attempted_at desc);

revoke all on public.auth_failed_login_attempts from anon, authenticated, public;
alter table public.auth_failed_login_attempts enable row level security;

create or replace function public.hook_password_verification_attempt(event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid;
  v_valid boolean;
  v_tenant_id text;
  v_max_failed integer;
  v_window interval := interval '15 minutes';
  v_recent_failures integer;
begin
  begin
    v_user_id := (event->>'user_id')::uuid;
    v_valid := coalesce((event->>'valid')::boolean, false);

    if v_user_id is null then
      return jsonb_build_object('decision', 'continue');
    end if;

    -- Bug fixed 2026-09-13 (found while wiring this into the SF-01 gap
    -- closure pass): this used to return 'continue' immediately for a
    -- CORRECT password, without ever checking the recent-failures count.
    -- That meant a locked-out account could still log in with the right
    -- password once the correct one was finally tried — the lockout only
    -- ever bit on the *wrong* password, never on the right one, which
    -- defeats the point of a lockout. The count must gate both paths.
    select (u.tenant_id), coalesce((s.security_policy->>'max_failed_logins')::integer, 5)
      into v_tenant_id, v_max_failed
      from public.users u
      left join public.admin_settings s on s.tenant_id = u.tenant_id
      where u.user_id = v_user_id::text;

    if v_max_failed is null then
      v_max_failed := 5;
    end if;

    if v_valid then
      select count(*) into v_recent_failures
        from public.auth_failed_login_attempts
        where user_id = v_user_id and attempted_at >= now() - v_window;

      if v_recent_failures >= v_max_failed then
        return jsonb_build_object(
          'decision', 'reject',
          'message', 'الحساب مقفل مؤقتاً بسبب محاولات دخول فاشلة متكررة. حاول لاحقاً.'
        );
      end if;

      delete from public.auth_failed_login_attempts where user_id = v_user_id;
      return jsonb_build_object('decision', 'continue');
    end if;

    delete from public.auth_failed_login_attempts
      where user_id = v_user_id and attempted_at < now() - v_window;

    insert into public.auth_failed_login_attempts (user_id, attempted_at)
      values (v_user_id, now());

    select count(*) into v_recent_failures
      from public.auth_failed_login_attempts
      where user_id = v_user_id and attempted_at >= now() - v_window;

    if v_recent_failures >= v_max_failed then
      return jsonb_build_object(
        'decision', 'reject',
        'message', 'الحساب مقفل مؤقتاً بسبب محاولات دخول فاشلة متكررة. حاول لاحقاً.'
      );
    end if;

    return jsonb_build_object('decision', 'continue');
  exception when others then
    return jsonb_build_object('decision', 'continue');
  end;
end;
$$;

revoke execute on function public.hook_password_verification_attempt(jsonb)
  from anon, authenticated, public;
grant execute on function public.hook_password_verification_attempt(jsonb)
  to supabase_auth_admin;
