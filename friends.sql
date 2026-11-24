-- 현실퀘스트 친구 기능 (setup.sql 다음에 한 번 실행)
-- 로그인용 회원코드와 별개인 '친구코드'를 쓰고, 친구에게는 용사 이름·직업·기록만 보여줍니다 (할 일 내용은 비공개).

alter table public.rq_users add column if not exists friend_code text unique;
alter table public.rq_users add column if not exists nick text;

create table if not exists public.rq_friends (
  a          text not null references public.rq_users(code) on delete cascade,
  b          text not null references public.rq_users(code) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (a, b)
);
alter table public.rq_friends enable row level security;
revoke all on public.rq_friends from anon, authenticated;

-- 내부용: 친구코드가 없으면 만들어 주기
create or replace function public.rq_ensure_friend_code(p_code text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare
  alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  f text; i int; tries int := 0;
begin
  select friend_code into f from rq_users where code = p_code;
  if f is not null then return f; end if;
  loop
    f := '';
    for i in 1..6 loop
      f := f || substr(alphabet, 1 + (get_byte(gen_random_bytes(1), 0) % 32), 1);
    end loop;
    exit when not exists (select 1 from rq_users where friend_code = f or code = f);
    tries := tries + 1;
    if tries > 20 then raise exception 'friend code generation failed'; end if;
  end loop;
  update rq_users set friend_code = f where code = p_code;
  return f;
end $$;

-- 내 친구코드·이름
create or replace function public.rq_profile(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); f text; n text;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  f := rq_ensure_friend_code(c);
  select nick into n from rq_users where code = c;
  return json_build_object('ok', true, 'friend_code', f, 'nick', coalesce(n, '모험가 ' || left(f, 3)));
end $$;

create or replace function public.rq_set_nick(p_token text, p_nick text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); n text := btrim(coalesce(p_nick, ''));
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  if char_length(n) < 1 or char_length(n) > 12 then return json_build_object('ok', false, 'error', 'NICK_FORMAT'); end if;
  update rq_users set nick = n where code = c;
  return json_build_object('ok', true, 'nick', n);
end $$;

-- 친구코드로 친구 추가 (서로 친구가 됨, 최대 50명)
create or replace function public.rq_add_friend(p_token text, p_friend_code text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); other text; fc text := upper(btrim(coalesce(p_friend_code, '')));
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  select code into other from rq_users where friend_code = fc;
  if other is null then perform pg_sleep(0.3); return json_build_object('ok', false, 'error', 'NOT_FOUND'); end if;
  if other = c then return json_build_object('ok', false, 'error', 'SELF'); end if;
  if exists (select 1 from rq_friends where a = c and b = other) then
    return json_build_object('ok', false, 'error', 'ALREADY');
  end if;
  if (select count(*) from rq_friends where a = c) >= 50 then
    return json_build_object('ok', false, 'error', 'TOO_MANY');
  end if;
  insert into rq_friends(a, b) values (c, other), (other, c) on conflict do nothing;
  return json_build_object('ok', true);
end $$;

-- 친구 끊기 (양쪽 모두)
create or replace function public.rq_remove_friend(p_token text, p_friend_code text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); other text;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  select code into other from rq_users where friend_code = upper(btrim(coalesce(p_friend_code, '')));
  delete from rq_friends where (a = c and b = other) or (a = other and b = c);
  return json_build_object('ok', true);
end $$;

-- 친구 목록: 이름과 용사 기록 (할 일 내용은 빼고)
create or replace function public.rq_friends(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare c text := rq_session_code(p_token); res json;
begin
  if c is null then return json_build_object('ok', false, 'error', 'NO_SESSION'); end if;
  select coalesce(json_agg(json_build_object(
           'friend_code', rq_ensure_friend_code(u.code),
           'nick', coalesce(u.nick, '모험가 ' || left(rq_ensure_friend_code(u.code), 3)),
           'heroes', coalesce((select jsonb_agg(h - 'task') from jsonb_array_elements(u.data -> 'heroes') h), '[]'::jsonb)
         ) order by f.created_at), '[]'::json)
    into res
    from rq_friends f join rq_users u on u.code = f.b
   where f.a = c;
  return json_build_object('ok', true, 'friends', res);
end $$;

revoke all on function public.rq_ensure_friend_code(text) from public, anon, authenticated;
grant execute on function public.rq_profile(text), public.rq_set_nick(text, text), public.rq_add_friend(text, text),
  public.rq_remove_friend(text, text), public.rq_friends(text) to anon, authenticated;
