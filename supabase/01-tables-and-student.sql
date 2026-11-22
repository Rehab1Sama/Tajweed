-- مختبر التجويد: الجداول ودوال الطالبات (كلها تبدأ بـ tj_)
-- يُطبَّق أولًا، ثم 02-admin.sql. لا يحتوي أي رمز سري.
-- الوصول من الموقع عبر دوال SECURITY DEFINER فقط، والجداول مقفلة (RLS بلا سياسات).

create extension if not exists pgcrypto with schema extensions;

create table if not exists tj_settings(key text primary key, value jsonb not null);

create table if not exists tj_students(
  id bigserial primary key,
  name text not null,
  name_key text not null unique,
  pin_hash text not null,
  circle text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  last_seen timestamptz
);

create table if not exists tj_sessions(
  token uuid primary key default gen_random_uuid(),
  student_id bigint not null references tj_students(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists tj_sessions_student on tj_sessions(student_id);

create table if not exists tj_admin_sessions(
  token uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now()
);

create table if not exists tj_attempts(
  id bigserial primary key,
  k text not null,
  at timestamptz not null default now()
);
create index if not exists tj_attempts_k on tj_attempts(k, at);

create table if not exists tj_words(station text primary key, word text not null);

create table if not exists tj_listens(
  student_id bigint not null references tj_students(id) on delete cascade,
  station text not null,
  created_at timestamptz not null default now(),
  primary key(student_id, station)
);

create table if not exists tj_progress(
  student_id bigint not null references tj_students(id) on delete cascade,
  station text not null,
  attempts int not null default 0,
  best_score int,
  best_total int,
  first_score int,
  first_total int,
  stamped_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key(student_id, station)
);

create table if not exists tj_assignments(
  id bigserial primary key,
  title text not null,
  note text,
  kind text not null default 'hw',
  minutes int,
  stations jsonb not null default '[]'::jsonb,
  qcount int not null default 0,
  custom jsonb not null default '[]'::jsonb,
  due_at timestamptz,
  target_circle text,
  target_students jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists tj_answers(
  id bigserial primary key,
  student_id bigint not null references tj_students(id) on delete cascade,
  source text not null,
  station text,
  question text not null,
  correct boolean not null,
  assignment_id bigint references tj_assignments(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists tj_answers_student on tj_answers(student_id, created_at);
create index if not exists tj_answers_assignment on tj_answers(assignment_id);

create table if not exists tj_submissions(
  assignment_id bigint not null references tj_assignments(id) on delete cascade,
  student_id bigint not null references tj_students(id) on delete cascade,
  score int not null,
  total int not null,
  tries int not null default 1,
  details jsonb,
  updated_at timestamptz not null default now(),
  primary key(assignment_id, student_id)
);

create table if not exists tj_game_plays(
  id bigserial primary key,
  student_id bigint not null references tj_students(id) on delete cascade,
  game text not null,
  score int not null,
  max int not null,
  created_at timestamptz not null default now()
);
create index if not exists tj_game_plays_student on tj_game_plays(student_id);

-- إغلاق الجداول: لا وصول مباشر من المتصفح
do $$ declare t text; begin
  for t in select unnest(array['tj_settings','tj_students','tj_sessions','tj_admin_sessions','tj_attempts','tj_words','tj_listens','tj_progress','tj_assignments','tj_answers','tj_submissions','tj_game_plays']) loop
    execute format('alter table %I enable row level security', t);
    execute format('revoke all on table %I from anon, authenticated', t);
  end loop;
end $$;
revoke all on all sequences in schema public from anon, authenticated;

-- ===== دوال مساعدة (لا تُستدعى من المتصفح) =====
create or replace function tj_norm(t text) returns text
language sql immutable set search_path = public as $$
  select lower(btrim(regexp_replace(
    translate(regexp_replace(coalesce(t,''), '[ً-ْـ]', '', 'g'), 'أإآى', 'اااي'),
    '\s+', ' ', 'g')))
$$;

create or replace function tj_digits(t text) returns text
language sql immutable set search_path = public as $$
  select translate(btrim(coalesce(t,'')), '٠١٢٣٤٥٦٧٨٩', '0123456789')
$$;

create or replace function tj_stations() returns text[]
language sql immutable set search_path = public as $$
  select array['mabadi','maratib','noon','meem','madd','makharij','sifat','alaqat','wasl','tafkheem','waqf']
$$;

create or replace function tj_setting(p_key text) returns jsonb
language sql stable security definer set search_path = public as $$
  select value from tj_settings where key = p_key
$$;

create or replace function tj_lock_check(p_key text, p_limit int default 8) returns void
language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from tj_attempts a where a.k = p_key and a.at > now() - interval '15 minutes') >= p_limit then
    raise exception 'LOCKED';
  end if;
end $$;

create or replace function tj_fail(p_key text) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into tj_attempts(k) values (p_key);
  delete from tj_attempts where at < now() - interval '1 day';
end $$;

create or replace function tj_ok(p_key text) returns void
language sql security definer set search_path = public as $$
  delete from tj_attempts where k = p_key
$$;

create or replace function tj_sid(p_token text) returns bigint
language plpgsql security definer set search_path = public as $$
declare t uuid; sid bigint;
begin
  begin t := p_token::uuid; exception when others then raise exception 'SESSION'; end;
  select s.student_id into sid
    from tj_sessions s join tj_students st on st.id = s.student_id
   where s.token = t and st.active and s.created_at > now() - interval '180 days';
  if sid is null then raise exception 'SESSION'; end if;
  update tj_students set last_seen = now()
   where id = sid and (last_seen is null or last_seen < now() - interval '5 minutes');
  return sid;
end $$;

create or replace function tj_adm(p_token text) returns void
language plpgsql security definer set search_path = public as $$
declare t uuid;
begin
  begin t := p_token::uuid; exception when others then raise exception 'ADMIN'; end;
  if not exists (select 1 from tj_admin_sessions where token = t and created_at > now() - interval '90 days') then
    raise exception 'ADMIN';
  end if;
end $$;

revoke all on function tj_norm(text), tj_digits(text), tj_stations(), tj_setting(text),
  tj_lock_check(text,int), tj_fail(text), tj_ok(text), tj_sid(text), tj_adm(text)
  from public, anon, authenticated;

-- ===== دوال الطالبات =====
create or replace function tj_public_settings() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object(
    'join_open',   coalesce(tj_setting('join_open'), 'false'::jsonb),
    'level2_open', coalesce(tj_setting('level2_open'), 'false'::jsonb))
$$;

create or replace function tj_student_register(p_name text, p_pin text, p_circle text, p_code text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  nm text := btrim(regexp_replace(coalesce(p_name,''), '\s+', ' ', 'g'));
  pin text := tj_digits(p_pin);
  k text := 'r:' || tj_norm(coalesce(p_name,''));
  stored text := btrim(coalesce(tj_setting('join_code') #>> '{}', ''));
  sid bigint; tok uuid;
begin
  perform tj_lock_check(k);
  perform tj_lock_check('reg', 40);
  if coalesce(tj_setting('join_open') #>> '{}', 'false') <> 'true' then
    return json_build_object('ok', false, 'error', 'CLOSED');
  end if;
  if length(nm) < 3 or position(' ' in nm) = 0 then return json_build_object('ok', false, 'error', 'NAME'); end if;
  if pin !~ '^[0-9]{4,8}$' then return json_build_object('ok', false, 'error', 'PIN'); end if;
  if stored = '' or tj_norm(p_code) <> tj_norm(stored) then
    perform tj_fail(k); perform tj_fail('reg');
    return json_build_object('ok', false, 'error', 'CODE');
  end if;
  if exists (select 1 from tj_students where name_key = tj_norm(nm)) then
    return json_build_object('ok', false, 'error', 'DUP');
  end if;
  insert into tj_students(name, name_key, pin_hash, circle, last_seen)
  values (nm, tj_norm(nm), crypt(pin, gen_salt('bf')), nullif(btrim(coalesce(p_circle,'')), ''), now())
  returning id into sid;
  insert into tj_sessions(student_id) values (sid) returning token into tok;
  perform tj_ok(k);
  return json_build_object('ok', true, 'token', tok, 'name', nm);
end $$;

create or replace function tj_student_login(p_name text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  k text := 'u:' || tj_norm(coalesce(p_name,''));
  st tj_students%rowtype; tok uuid;
begin
  perform tj_lock_check(k);
  select * into st from tj_students where name_key = tj_norm(p_name) and active;
  if not found or st.pin_hash <> crypt(tj_digits(p_pin), st.pin_hash) then
    perform tj_fail(k);
    return json_build_object('ok', false);
  end if;
  perform tj_ok(k);
  insert into tj_sessions(student_id) values (st.id) returning token into tok;
  update tj_students set last_seen = now() where id = st.id;
  delete from tj_sessions where student_id = st.id and created_at < now() - interval '180 days';
  return json_build_object('ok', true, 'token', tok, 'name', st.name);
end $$;

create or replace function tj_student_state(p_token text) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token); mine text;
begin
  select tj_norm(circle) into mine from tj_students where id = sid;
  return json_build_object(
    'listened', coalesce((select json_agg(station) from tj_listens where student_id = sid), '[]'::json),
    'word_for', coalesce((select json_agg(station) from tj_words where btrim(word) <> ''), '[]'::json),
    'level2_open', coalesce(tj_setting('level2_open') #>> '{}', 'false') = 'true',
    'progress', coalesce((select json_agg(json_build_object('station', station, 'stamped', stamped_at is not null, 'attempts', attempts))
                            from tj_progress where student_id = sid), '[]'::json),
    'assignments', coalesce((
      select json_agg(json_build_object('id', a.id, 'title', a.title, 'note', a.note, 'kind', a.kind, 'minutes', a.minutes,
                                        'due_at', a.due_at, 'stations', a.stations, 'qcount', a.qcount, 'custom', a.custom,
                                        'score', s.score, 'total', s.total) order by a.created_at desc)
        from tj_assignments a
        left join tj_submissions s on s.assignment_id = a.id and s.student_id = sid
       where a.active and (
             (a.target_circle is null and a.target_students is null)
          or (a.target_circle is not null and tj_norm(a.target_circle) = mine)
          or (a.target_students is not null and a.target_students ? sid::text))
    ), '[]'::json));
end $$;

create or replace function tj_mark_listened(p_token text, p_station text, p_word text) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token); w text; k text;
begin
  if not (p_station = any (tj_stations())) then return json_build_object('ok', false, 'error', 'STATION'); end if;
  k := 'w:' || sid;
  perform tj_lock_check(k, 15);
  select word into w from tj_words where station = p_station;
  if w is not null and btrim(w) <> '' and tj_norm(p_word) <> tj_norm(w) then
    perform tj_fail(k);
    return json_build_object('ok', false, 'error', 'WORD');
  end if;
  insert into tj_listens(student_id, station) values (sid, p_station) on conflict do nothing;
  return json_build_object('ok', true);
end $$;

create or replace function tj_save_answers(p_token text, p_items jsonb) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token); n int := 0;
begin
  if p_items is null or jsonb_typeof(p_items) <> 'array' then return json_build_object('ok', false); end if;
  insert into tj_answers(student_id, source, station, question, correct, assignment_id)
  select sid,
         left(coalesce(i ->> 'source', 'lab'), 20),
         nullif(left(coalesce(i ->> 'station', ''), 30), ''),
         left(coalesce(i ->> 'question', ''), 500),
         coalesce((i ->> 'correct')::boolean, false),
         (select a.id from tj_assignments a where a.id = nullif(i ->> 'assignment_id', '')::bigint)
    from (select value as i from jsonb_array_elements(p_items) limit 200) x;
  get diagnostics n = row_count;
  return json_build_object('ok', true, 'n', n);
end $$;

create or replace function tj_save_gate(p_token text, p_station text, p_score int, p_total int) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token); pass boolean;
begin
  if not (p_station = any (tj_stations())) or p_total is null or p_score is null
     or p_total < 1 or p_total > 100 or p_score < 0 or p_score > p_total then
    return json_build_object('ok', false);
  end if;
  pass := p_score >= ceil(p_total * 0.8);
  insert into tj_progress(student_id, station, attempts, best_score, best_total, first_score, first_total, stamped_at, updated_at)
  values (sid, p_station, 1, p_score, p_total, p_score, p_total, case when pass then now() end, now())
  on conflict (student_id, station) do update set
    attempts = tj_progress.attempts + 1,
    best_score = greatest(coalesce(tj_progress.best_score, 0), excluded.best_score),
    best_total = case when excluded.best_score >= coalesce(tj_progress.best_score, 0) then excluded.best_total else tj_progress.best_total end,
    stamped_at = coalesce(tj_progress.stamped_at, excluded.stamped_at),
    updated_at = now();
  return json_build_object('ok', true, 'pass', pass);
end $$;

create or replace function tj_submit_assignment(p_token text, p_assignment bigint, p_score int, p_total int, p_details jsonb) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token); k text;
begin
  if p_score is null or p_total is null or p_total < 1 or p_total > 200 or p_score < 0 or p_score > p_total then
    return json_build_object('ok', false, 'error', 'BAD');
  end if;
  select kind into k from tj_assignments where id = p_assignment and active;
  if not found then return json_build_object('ok', false, 'error', 'NONE'); end if;
  if k = 'exam' and exists (select 1 from tj_submissions where assignment_id = p_assignment and student_id = sid) then
    return json_build_object('ok', true, 'locked', true);
  end if;
  insert into tj_submissions(assignment_id, student_id, score, total, tries, details)
  values (p_assignment, sid, p_score, p_total, 1, p_details)
  on conflict (assignment_id, student_id) do update set
    score = greatest(tj_submissions.score, excluded.score),
    total = case when excluded.score >= tj_submissions.score then excluded.total else tj_submissions.total end,
    details = case when excluded.score > tj_submissions.score then excluded.details else tj_submissions.details end,
    tries = tj_submissions.tries + 1,
    updated_at = now();
  return json_build_object('ok', true);
end $$;

create or replace function tj_save_game(p_token text, p_game text, p_score int, p_max int) returns json
language plpgsql security definer set search_path = public as $$
declare sid bigint := tj_sid(p_token);
begin
  if p_game is null or length(p_game) < 1 or length(p_game) > 40 or p_score is null or p_max is null
     or p_score < 0 or p_max < 1 or p_max > 100000 or p_score > p_max * 10 then
    return json_build_object('ok', false);
  end if;
  insert into tj_game_plays(student_id, game, score, max) values (sid, p_game, p_score, p_max);
  return json_build_object('ok', true);
end $$;
