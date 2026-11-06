-- ============================================================
--  Tabla de roles para el ejemplo de login (MAUI + Supabase)
--  Ejecutar en: Supabase Dashboard → SQL Editor
-- ============================================================

-- 1) La tabla de roles. Una fila por usuario de auth.users.
create table if not exists public.user_roles (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text not null,
  role       text not null default 'viewer' check (role in ('admin','editor','viewer')),
  created_at timestamptz not null default now()
);

alter table public.user_roles enable row level security;

-- 2) Función auxiliar: ¿el usuario actual es admin?
--    security definer evita la recursión infinita de RLS al consultar la misma tabla dentro de una política.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'admin');
$$;

-- 3) Políticas (RLS): se evalúan en el servidor con el JWT que envía la app.
create policy "cada usuario lee su propio rol"
  on public.user_roles for select
  using (user_id = auth.uid());

create policy "admin lee todos los roles"
  on public.user_roles for select
  using (public.is_admin());

create policy "admin cambia roles"
  on public.user_roles for update
  using (public.is_admin())
  with check (public.is_admin());

-- (No hay política de insert/delete: nadie desde el cliente crea roles; lo hace el trigger.)

-- 4) Trigger: cuando alguien se registra, se le asigna 'viewer' automáticamente.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.user_roles (user_id, email, role)
  values (new.id, new.email, 'viewer');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 5) Convierte a tu usuario en admin (después de registrarte desde la app):
-- update public.user_roles set role = 'admin' where email = 'tu-correo@gmail.com';
