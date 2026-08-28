-- =====================================================
-- SEVER DC Web Console v0.2
-- 帳號管理 + LOG 查詢中心
-- =====================================================

drop policy if exists
"sever_admin_profiles_select_approved_admins"
on public.sever_admin_profiles;

create policy "sever_admin_profiles_select_approved_admins"
on public.sever_admin_profiles
for select
to authenticated
using (
    public.is_approved_sever_admin(auth.uid())
);

grant select
on table public.sever_admin_profiles
to authenticated;

alter table public.sever_logs
enable row level security;

drop policy if exists
"sever_logs_select_approved_admins"
on public.sever_logs;

create policy "sever_logs_select_approved_admins"
on public.sever_logs
for select
to authenticated
using (
    public.is_approved_sever_admin(auth.uid())
);

grant select
on table public.sever_logs
to authenticated;

alter table public.sever_admin_audit
enable row level security;

drop policy if exists
"sever_admin_audit_select_approved_admins"
on public.sever_admin_audit;

create policy "sever_admin_audit_select_approved_admins"
on public.sever_admin_audit
for select
to authenticated
using (
    public.is_approved_sever_admin(auth.uid())
);

grant select
on table public.sever_admin_audit
to authenticated;

create or replace function public.set_sever_admin_approval(
    p_target_user_id uuid,
    p_approved boolean
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
    v_uid uuid;
    v_exists boolean;
begin
    v_uid := auth.uid();

    if v_uid is null then
        raise exception 'Not authenticated';
    end if;

    if not public.is_approved_sever_admin(v_uid) then
        raise exception 'Admin account is not approved';
    end if;

    if p_target_user_id is null then
        raise exception 'Target user is required';
    end if;

    if p_approved is null then
        raise exception 'Approval value is required';
    end if;

    if p_target_user_id = v_uid and p_approved = false then
        raise exception 'You cannot revoke your own admin access';
    end if;

    select exists (
        select 1
        from public.sever_admin_profiles
        where user_id = p_target_user_id
    )
    into v_exists;

    if not v_exists then
        raise exception 'Target admin profile not found';
    end if;

    update public.sever_admin_profiles
    set
        approved = p_approved,
        approved_at = case
            when p_approved = true then coalesce(approved_at, now())
            else null
        end
    where user_id = p_target_user_id;

    return true;
end;
$$;

revoke all
on function public.set_sever_admin_approval(uuid, boolean)
from public;

grant execute
on function public.set_sever_admin_approval(uuid, boolean)
to authenticated;

revoke insert, update, delete
on table public.sever_admin_profiles
from anon, authenticated;

select 'SEVER DC Web Console v0.2 ready' as status;
