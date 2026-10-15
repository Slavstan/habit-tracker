-- Habit Tracker schema for Supabase.
-- Run in Supabase Dashboard -> SQL Editor -> New query.

-- A profile row is created automatically when a new Auth user registers.
create table if not exists public.users (
  id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.habits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 100),
  description text check (description is null or char_length(description) <= 500),
  created_at timestamptz not null default now()
);

create index if not exists habits_user_id_created_at_idx
  on public.habits (user_id, created_at);

create table if not exists public.habit_logs (
  id uuid primary key default gen_random_uuid(),
  habit_id uuid not null references public.habits (id) on delete cascade,
  date date not null,
  created_at timestamptz not null default now(),
  constraint habit_logs_habit_id_date_key unique (habit_id, date)
);

create index if not exists habit_logs_habit_id_date_idx
  on public.habit_logs (habit_id, date);

-- Create a public.users row for each new Supabase Auth account.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.users (id) values (new.id);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.users enable row level security;
alter table public.habits enable row level security;
alter table public.habit_logs enable row level security;

-- Users can read only their own profile. Inserts are handled by the trigger.
drop policy if exists "Users can view own profile" on public.users;
create policy "Users can view own profile"
  on public.users for select to authenticated
  using ((select auth.uid()) = id);

drop policy if exists "Users can view own habits" on public.habits;
create policy "Users can view own habits"
  on public.habits for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users can create own habits" on public.habits;
create policy "Users can create own habits"
  on public.habits for insert to authenticated
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update own habits" on public.habits;
create policy "Users can update own habits"
  on public.habits for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete own habits" on public.habits;
create policy "Users can delete own habits"
  on public.habits for delete to authenticated
  using ((select auth.uid()) = user_id);

-- A log is accessible only when its parent habit belongs to the signed-in user.
drop policy if exists "Users can view own habit logs" on public.habit_logs;
create policy "Users can view own habit logs"
  on public.habit_logs for select to authenticated
  using (
    exists (
      select 1 from public.habits h
      where h.id = habit_logs.habit_id
        and h.user_id = (select auth.uid())
    )
  );

drop policy if exists "Users can create own habit logs" on public.habit_logs;
create policy "Users can create own habit logs"
  on public.habit_logs for insert to authenticated
  with check (
    exists (
      select 1 from public.habits h
      where h.id = habit_logs.habit_id
        and h.user_id = (select auth.uid())
    )
  );

drop policy if exists "Users can delete own habit logs" on public.habit_logs;
create policy "Users can delete own habit logs"
  on public.habit_logs for delete to authenticated
  using (
    exists (
      select 1 from public.habits h
      where h.id = habit_logs.habit_id
        and h.user_id = (select auth.uid())
    )
  );

-- Supabase commonly grants these roles table access; RLS policies above
-- constrain which rows authenticated users can read or change.
grant select on public.users to authenticated;
grant select, insert, update, delete on public.habits to authenticated;
grant select, insert, delete on public.habit_logs to authenticated;
