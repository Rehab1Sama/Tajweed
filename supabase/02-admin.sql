-- مختبر التجويد: دوال لوحة المعلمة (تتحقق من رمز جلسة المعلمة في كل استدعاء)
-- الرمز السري للمعلمة ورمز الانضمام لا يُكتبان هنا؛ يُضبطان في جدول tj_settings
-- (admin_pin_hash, join_code, join_open, level2_open) ويمكن تغييرهما من لوحة المعلمة.

create or replace function tj_admin_login(p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare h text := tj_setting('admin_pin_hash') #>> '{}'; tok uuid;
begin
  perform tj_lock_check('admin');
  if h is null or h <> crypt(tj_digits(p_pin), h) then
    perform tj_fail('admin');
    return json_build_object('ok', false);
  end if;
  perform tj_ok('admin');
  insert into tj_admin_sessions default values returning token into tok;
  delete from tj_admin_sessions where created_at < now() - interval '90 days';
  return json_build_object('ok', true, 'token', tok);
end $$;

create or replace function tj_admin_change_pin(p_token text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare pin text := tj_digits(p_pin);
begin
  perform tj_adm(p_token);
  if pin !~ '^[0-9]{6,20}$' then return json_build_object('ok', false); end if;
  insert into tj_settings(key, value) values ('admin_pin_hash', to_jsonb(crypt(pin, gen_salt('bf'))))
  on conflict (key) do update set value = excluded.value;
  return json_build_object('ok', true);
end $$;

create or replace function tj_admin_set_setting(p_token text, p_key text, p_value jsonb) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  if p_key in ('level2_open', 'join_open') then
    insert into tj_settings(key, value) values (p_key, to_jsonb(coalesce(p_value #>> '{}', 'false') = 'true'))
    on conflict (key) do update set value = excluded.value;
  elsif p_key = 'join_code' then
    insert into tj_settings(key, value) values (p_key, to_jsonb(left(btrim(coalesce(p_value #>> '{}', '')), 40)))
    on conflict (key) do update set value = excluded.value;
  else
    return json_build_object('ok', false);
  end if;
  return json_build_object('ok', true);
end $$;

create or replace function tj_admin_join(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  return json_build_object('open', coalesce(tj_setting('join_open') #>> '{}', 'false') = 'true',
                           'code', coalesce(tj_setting('join_code') #>> '{}', ''));
end $$;

create or replace function tj_admin_set_word(p_token text, p_station text, p_word text) returns json
language plpgsql security definer set search_path = public as $$
declare w text := left(btrim(coalesce(p_word, '')), 100);
begin
  perform tj_adm(p_token);
  if not (p_station = any (tj_stations())) then return json_build_object('ok', false); end if;
  if w = '' then
    delete from tj_words where station = p_station;
  else
    insert into tj_words(station, word) values (p_station, w)
    on conflict (station) do update set word = excluded.word;
  end if;
  return json_build_object('ok', true);
end $$;

create or replace function tj_admin_overview(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  return json_build_object(
    'students', coalesce((select json_agg(json_build_object(
        'id', s.id, 'name', s.name, 'circle', s.circle, 'active', s.active,
        'answered',   (select count(*) from tj_answers a where a.student_id = s.id),
        'correct',    (select count(*) from tj_answers a where a.student_id = s.id and a.correct),
        'answered14', (select count(*) from tj_answers a where a.student_id = s.id and a.created_at > now() - interval '14 days'),
        'correct14',  (select count(*) from tj_answers a where a.student_id = s.id and a.correct and a.created_at > now() - interval '14 days'),
        'stamped',    (select count(*) from tj_progress p where p.student_id = s.id and p.stamped_at is not null),
        'last_seen',  s.last_seen) order by s.name) from tj_students s), '[]'::json),
    'stations', coalesce((select json_agg(json_build_object('station', x.station, 'answered', x.n, 'correct', x.c))
        from (select a.station, count(*) n, count(*) filter (where a.correct) c
                from tj_answers a join tj_students s on s.id = a.student_id and s.active
               where a.station is not null group by a.station) x), '[]'::json),
    'stamps', coalesce((select json_agg(json_build_object('station', x.station, 'stamped', x.n))
        from (select p.station, count(*) n
                from tj_progress p join tj_students s on s.id = p.student_id and s.active
               where p.stamped_at is not null group by p.station) x), '[]'::json),
    'missed', coalesce((select json_agg(json_build_object('question', m.question, 'station', m.station, 'wrong', m.w, 'total', m.n) order by m.w desc, m.n desc)
        from (select a.question, a.station, count(*) filter (where not a.correct) w, count(*) n
                from tj_answers a join tj_students s on s.id = a.student_id and s.active
               group by a.question, a.station
              having count(*) filter (where not a.correct) > 0
               order by w desc, n desc limit 30) m), '[]'::json),
    'circles', coalesce((select json_agg(x.c order by x.c)
        from (select distinct circle c from tj_students where active and circle is not null and btrim(circle) <> '') x), '[]'::json),
    'assignments', coalesce((select json_agg(json_build_object(
        'id', a.id, 'title', a.title, 'kind', a.kind, 'minutes', a.minutes,
        'avg',  (select avg(s.score::float / s.total) from tj_submissions s where s.assignment_id = a.id),
        'subs', (select count(*) from tj_submissions s where s.assignment_id = a.id),
        'target_circle', a.target_circle, 'due_at', a.due_at, 'active', a.active) order by a.created_at desc)
        from tj_assignments a), '[]'::json));
end $$;

create or replace function tj_admin_student(p_token text, p_id bigint) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  if not exists (select 1 from tj_students where id = p_id) then raise exception 'NOSTUDENT'; end if;
  return json_build_object(
    'progress', coalesce((select json_agg(json_build_object('station', station, 'stamped_at', stamped_at,
                 'first_score', first_score, 'first_total', first_total, 'attempts', attempts))
                 from tj_progress where student_id = p_id), '[]'::json),
    'stations', coalesce((select json_agg(json_build_object('station', x.station, 'answered', x.n, 'correct', x.c))
                 from (select station, count(*) n, count(*) filter (where correct) c
                         from tj_answers where student_id = p_id and station is not null group by station) x), '[]'::json),
    'activity', coalesce((select json_agg(json_build_object('d', x.d, 'n', x.n) order by x.d)
                 from (select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD') d, count(*) n
                         from tj_answers where student_id = p_id and created_at > now() - interval '30 days' group by 1) x), '[]'::json),
    'subs', coalesce((select json_agg(json_build_object('title', a.title, 'kind', a.kind, 'score', s.score, 'total', s.total, 'tries', s.tries) order by s.updated_at desc)
                 from tj_submissions s join tj_assignments a on a.id = s.assignment_id where s.student_id = p_id), '[]'::json),
    'games', coalesce((select json_agg(json_build_object('game', g.game, 'best', g.best, 'max', g.mx, 'plays', g.n) order by g.game)
                 from (select gp.game, max(gp.score) best, max(gp.max) mx, count(*) n
                         from tj_game_plays gp where gp.student_id = p_id group by gp.game) g), '[]'::json),
    'wrong', coalesce((select json_agg(json_build_object('question', w.question, 'station', w.station))
                 from (select question, station from tj_answers
                        where student_id = p_id and not correct order by created_at desc limit 15) w), '[]'::json));
end $$;

create or replace function tj_admin_save_student(p_token text, p_id bigint, p_name text, p_pin text, p_circle text, p_active boolean) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  nm text := btrim(regexp_replace(coalesce(p_name, ''), '\s+', ' ', 'g'));
  pin text := tj_digits(p_pin);
  sid bigint;
begin
  perform tj_adm(p_token);
  if length(nm) < 2 then return json_build_object('ok', false, 'error', 'NAME'); end if;
  if exists (select 1 from tj_students where name_key = tj_norm(nm) and (p_id is null or id <> p_id)) then
    return json_build_object('ok', false, 'error', 'DUP');
  end if;
  if p_id is null then
    if pin !~ '^[0-9]{4,8}$' then return json_build_object('ok', false, 'error', 'PIN'); end if;
    insert into tj_students(name, name_key, pin_hash, circle, active)
    values (nm, tj_norm(nm), crypt(pin, gen_salt('bf')), nullif(btrim(coalesce(p_circle, '')), ''), coalesce(p_active, true))
    returning id into sid;
  else
    if pin <> '' and pin !~ '^[0-9]{4,8}$' then return json_build_object('ok', false, 'error', 'PIN'); end if;
    update tj_students set
      name = nm, name_key = tj_norm(nm),
      circle = nullif(btrim(coalesce(p_circle, '')), ''),
      active = coalesce(p_active, true),
      pin_hash = case when pin <> '' then crypt(pin, gen_salt('bf')) else pin_hash end
    where id = p_id returning id into sid;
    if sid is null then return json_build_object('ok', false, 'error', 'NONE'); end if;
    if pin <> '' or not coalesce(p_active, true) then delete from tj_sessions where student_id = p_id; end if;
  end if;
  return json_build_object('ok', true, 'id', sid);
end $$;

create or replace function tj_admin_save_assignment(
  p_token text, p_title text, p_note text, p_stations jsonb, p_qcount int, p_custom jsonb,
  p_due text, p_circle text, p_students jsonb, p_kind text, p_minutes int) returns json
language plpgsql security definer set search_path = public as $$
declare
  st jsonb; cu jsonb; tg jsonb; due timestamptz; aid bigint; kd text; q int; circ text;
begin
  perform tj_adm(p_token);
  if btrim(coalesce(p_title, '')) = '' then return json_build_object('ok', false); end if;
  st := coalesce((select jsonb_agg(v) from jsonb_array_elements_text(
          case when jsonb_typeof(p_stations) = 'array' then p_stations else '[]'::jsonb end) v
          where v = any (tj_stations())), '[]'::jsonb);
  cu := case when jsonb_typeof(p_custom) = 'array' then p_custom else '[]'::jsonb end;
  tg := case when jsonb_typeof(p_students) = 'array' and jsonb_array_length(p_students) > 0
             then (select jsonb_agg(v) from jsonb_array_elements_text(p_students) v) end;
  q := case when jsonb_array_length(st) > 0 then greatest(0, least(50, coalesce(p_qcount, 0))) else 0 end;
  if q = 0 and jsonb_array_length(cu) = 0 then return json_build_object('ok', false); end if;
  begin due := nullif(p_due, '')::timestamptz; exception when others then due := null; end;
  kd := case when p_kind = 'exam' then 'exam' else 'hw' end;
  circ := case when tg is null then nullif(btrim(coalesce(p_circle, '')), '') end;
  insert into tj_assignments(title, note, kind, minutes, stations, qcount, custom, due_at, target_circle, target_students)
  values (left(btrim(p_title), 200), nullif(btrim(coalesce(p_note, '')), ''), kd,
          case when kd = 'exam' and p_minutes between 1 and 180 then p_minutes end,
          st, q, cu, due, circ, tg)
  returning id into aid;
  return json_build_object('ok', true, 'id', aid);
end $$;

create or replace function tj_admin_assignment(p_token text, p_id bigint) returns json
language plpgsql security definer set search_path = public as $$
declare a tj_assignments%rowtype;
begin
  perform tj_adm(p_token);
  select * into a from tj_assignments where id = p_id;
  if not found then raise exception 'NONE'; end if;
  return json_build_object(
    'rows', coalesce((select json_agg(json_build_object('name', s.name, 'score', sub.score, 'total', sub.total, 'tries', sub.tries) order by s.name)
              from tj_students s
              left join tj_submissions sub on sub.assignment_id = a.id and sub.student_id = s.id
             where s.active and (
                   (a.target_circle is null and a.target_students is null)
                or (a.target_circle is not null and tj_norm(a.target_circle) = tj_norm(s.circle))
                or (a.target_students is not null and a.target_students ? s.id::text))), '[]'::json),
    'missed', coalesce((select json_agg(json_build_object('question', m.question, 'station', null, 'wrong', m.w, 'total', m.n) order by m.w desc, m.n desc)
              from (select question, count(*) filter (where not correct) w, count(*) n
                      from tj_answers where assignment_id = p_id
                     group by question having count(*) filter (where not correct) > 0
                     order by w desc, n desc limit 20) m), '[]'::json));
end $$;

create or replace function tj_admin_toggle_assignment(p_token text, p_id bigint, p_active boolean) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  update tj_assignments set active = coalesce(p_active, false) where id = p_id;
  return json_build_object('ok', true);
end $$;

create or replace function tj_admin_listen(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  return json_build_object(
    'words', coalesce((select json_object_agg(station, word) from tj_words), '{}'::json),
    'counts', '[]'::json,
    'rows', coalesce((select json_agg(json_build_object('station', l.station, 'student_id', l.student_id, 'name', s.name, 'created_at', l.created_at))
              from tj_listens l join tj_students s on s.id = l.student_id and s.active), '[]'::json));
end $$;

create or replace function tj_admin_games(p_token text) returns json
language plpgsql security definer set search_path = public as $$
begin
  perform tj_adm(p_token);
  return json_build_object(
    'games', coalesce((select json_agg(json_build_object('game', g.game, 'avg', g.av, 'players', g.pl, 'plays', g.n, 'last_at', g.last_at) order by g.last_at desc)
              from (select gp.game, avg(gp.score::float / gp.max) av, count(distinct gp.student_id) pl, count(*) n, max(gp.created_at) last_at
                      from tj_game_plays gp group by gp.game) g), '[]'::json),
    'rows', coalesce((select json_agg(json_build_object('name', r.name, 'game', r.game, 'best', r.best, 'max', r.mx, 'plays', r.n) order by r.name, r.game)
              from (select s.id, s.name, gp.game, max(gp.score) best, max(gp.max) mx, count(*) n
                      from tj_game_plays gp join tj_students s on s.id = gp.student_id
                     group by s.id, s.name, gp.game) r), '[]'::json),
    'level2_open', coalesce(tj_setting('level2_open') #>> '{}', 'false') = 'true');
end $$;
