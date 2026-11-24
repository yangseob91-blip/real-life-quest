-- 현실퀘스트 로그인·저장 서버 설정 (Supabase SQL Editor에서 한 번 실행)
-- 회원코드 6자리 + 숫자 비밀번호 6자리. 비밀번호는 bcrypt로 암호화해 저장하고,
-- 로그인하면 기기마다 세션 토큰을 발급해 자동 로그인을 유지합니다.
-- 표는 직접 읽고 쓸 수 없게 막고, 아래 함수로만 접근합니다.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.rq_users (
  code         text primary key,
  pin_hash     text not null,
  data         jsonb not null default '{"heroes":[]}'::jsonb,
  fails        int not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.rq_sessions (
  token_hash text primary key,
  code       text not null references public.rq_users(code) on delete cascade,
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);
create index if not exists rq_sessions_code on public.rq_sessions(code);

alter table public.rq_users enable row level security;
alter table public.rq_sessions enable row level security;
revoke all on public.rq_users, public.rq_sessions from anon, authenticated;

-- 내부용: 세션 토큰 → 회원코드
create or replace function public.rq_session_code(p_token text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare c text;
begin
  update rq_sessions set last_used = now()
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
   returning code into c;
  return c;
end $$;

create or replace function public.rq_new_session(p_code text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(gen_random_bytes(24), 'hex');
begin
  insert into rq_sessions(token_hash, code) values (encode(digest(t, 'sha256'), 'hex'), p_code);
  return t;
end $$;

-- 처음 시작: 비밀번호를 받아 새 회원코드를 발급
create or replace function public.rq_register(p_pin text, p_data jsonb default null)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';  -- 헷갈리는 0 O 1 I 제외, 32글자
  c text; i int; tries int := 0;
begin
  if p_pin is null or p_pin !~ '^[0-9]{6}$' then
    return json_build_object('ok', false, 'error', 'PIN_FORMAT');
  end if;
  if p_data is not null and octet_length(p_data::text) > 300000 then
    return json_build_object('ok', false, 'error', 'TOO_BIG');
  end if;
  loop
    c := '';
    for i in 1..6 loop
      c := c || substr(alphabet, 1 + (get_byte(gen_random_bytes(1), 0) % 32), 1);
    end loop;
    exit when not exists (select 1 from rq_users where code = c);
    tries := tries + 1;
    if tries > 20 then return json_build_object('ok', false, 'error', 'TRY_AGAIN'); end if;
  end loop;
  insert into rq_users(code, pin_hash, data)
  values (c, crypt(p_pin, gen_salt('bf', 8)), coalesce(p_data, '{"heroes":[]}'::jsonb));
  return json_build_object('ok', true, 'code', c, 'token', rq_new_session(c),
                           'updated_at', (select updated_at from rq_users where code = c));
end $$;

-- 로그인: 5번 틀리면 15분 잠금, 이후 틀릴 때마다 잠금 시간 2배 (최대 16시간)
create or replace function public.rq_login(p_code text, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u rq_users; n int;
begin
  select * into u from rq_users where code = upper(trim(coalesce(p_code, ''))) for update;
  if not found or p_pin is null or p_pin !~ '^[0-9]{6}$' then
    perform pg_sleep(0.3);
    return json_build_object('ok', false, 'error', 'LOGIN_FAILED');
  end if;
  if u.locked_until is not null and u.locked_until > now() then
    return json_build_object('ok', false, 'error', 'LOCKED', 'until', u.locked_until);
  end if;
  if u.pin_hash <> crypt(p_pin, u.pin_hash) then
    n := u.fails + 1;
    update rq_users
       set fails = n,
           locked_until = case when n >= 5 then now() + interval '15 minutes' * power(2, least(n - 5, 6)) else null end
     where code = u.code;
    return json_build_object('ok', false, 'error', case when n >= 5 then 'LOCKED' else 'LOGIN_FAILED' end,
                             'left', greatest(0, 5 - n));
  end if;
  update rq_users set fails = 0, locked_until = null where code = u.code;
  return json_build_object('ok', true, 'code', u.code, 'token', rq_new_session(u.code),
                           'data', u.data, 'updated_at', u.updated_at);
end $$;

-- 자동 로그인 상태에서 기록 불러오기
create or replace function public.rq_load(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); u rq_users;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  select * into u from rq_users where code = c;
  return json_build_object('ok', true, 'code', u.code, 'data', u.data, 'updated_at', u.updated_at);
end $$;

-- 기록 저장
create or replace function public.rq_save(p_token text, p_data jsonb)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); t timestamptz;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  if p_data is null or jsonb_typeof(p_data -> 'heroes') <> 'array' then
    return json_build_object('ok', false, 'error', 'BAD_DATA');
  end if;
  if octet_length(p_data::text) > 300000 then return json_build_object('ok', false, 'error', 'TOO_BIG'); end if;
  update rq_users set data = p_data, updated_at = now() where code = c returning updated_at into t;
  return json_build_object('ok', true, 'updated_at', t);
end $$;

-- 비밀번호 바꾸기 (다른 기기의 자동 로그인은 모두 풀림)
create or replace function public.rq_change_pin(p_token text, p_old text, p_new text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); u rq_users;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  if p_new is null or p_new !~ '^[0-9]{6}$' then return json_build_object('ok', false, 'error', 'PIN_FORMAT'); end if;
  select * into u from rq_users where code = c;
  if u.pin_hash <> crypt(coalesce(p_old, ''), u.pin_hash) then
    return json_build_object('ok', false, 'error', 'WRONG_PIN');
  end if;
  update rq_users set pin_hash = crypt(p_new, gen_salt('bf', 8)) where code = c;
  delete from rq_sessions where code = c and token_hash <> encode(digest(p_token, 'sha256'), 'hex');
  return json_build_object('ok', true);
end $$;

-- 로그아웃 (이 기기만)
create or replace function public.rq_logout(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from rq_sessions where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return json_build_object('ok', true);
end $$;

revoke all on function public.rq_session_code(text), public.rq_new_session(text) from public, anon, authenticated;
grant execute on function public.rq_register(text, jsonb), public.rq_login(text, text), public.rq_load(text),
  public.rq_save(text, jsonb), public.rq_change_pin(text, text, text), public.rq_logout(text) to anon, authenticated;
