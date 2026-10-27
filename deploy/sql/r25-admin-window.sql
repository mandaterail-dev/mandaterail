-- R25-P3-1: open (window=open) or close (window=close) the deploy window in which
-- mr_admin may SET ROLE to the NOLOGIN table owner. Run as postgres:
--   psql -X -v ON_ERROR_STOP=1 -v window=open|close -f r25-admin-window.sql
-- deploy/mr-admin-window.sh wraps a deploy with open ... close (close runs on error too).
\if :{?window}
\else
\echo 'r25-admin-window.sql: pass -v window=open|close'
\quit
\endif
SELECT :'window' = 'open' AS w_open, :'window' = 'close' AS w_close \gset
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_admin') THEN RAISE EXCEPTION 'mr_admin does not exist (run the role SQL once with -v admin_pw)'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit') THEN RAISE EXCEPTION 'mr_spend_audit not found'; END IF;
END $$;
SELECT tableowner AS owner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit' \gset
\if :w_open
-- R26-P3-1: only inside a lock-holding window, and never on top of a leftover membership.
DO $$ DECLARE o text; m text; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  IF NOT EXISTS (SELECT 1 FROM pg_locks l WHERE l.locktype = 'advisory' AND l.granted AND l.classid = 26026 AND l.objid = 1 AND l.objsubid = 2
                   AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND l.pid <> pg_backend_pid()) THEN
    RAISE EXCEPTION 'no deploy-window lock holder (advisory lock 26026,1); open through deploy/mr-admin-window.sh';
  END IF;
  -- R27-P3-2: every holder must be this superuser's own mr-admin-window session (on the host: postgres).
  IF EXISTS (SELECT 1 FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid
              WHERE l.locktype = 'advisory' AND l.granted AND l.classid = 26026 AND l.objid = 1 AND l.objsubid = 2
                AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
                AND (a.usename IS DISTINCT FROM session_user OR a.application_name IS DISTINCT FROM 'mr-admin-window')) THEN
    RAISE EXCEPTION 'deploy-window lock (26026,1) is held by a session that is not %/mr-admin-window; refusing to open', session_user;
  END IF;
  SELECT string_agg(r.rolname, ', ' ORDER BY r.rolname) INTO m FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member
   WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = o);
  IF m IS NOT NULL THEN
    RAISE EXCEPTION 'refusing to open: % already member(s) of % (leftover window or drift); close it first (-v window=close)', m, o;
  END IF;
END $$;
GRANT :"owner" TO mr_admin WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
\elif :w_close
-- revoke every grant of the owner to mr_admin, whoever granted it
DO $$ DECLARE r record; o text; BEGIN
  SELECT tableowner INTO o FROM pg_tables WHERE schemaname = 'public' AND tablename = 'mr_spend_audit';
  FOR r IN SELECT gr.rolname AS grantor FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid
             JOIN pg_roles m ON m.oid = am.member JOIN pg_roles gr ON gr.oid = am.grantor
            WHERE m.rolname = 'mr_admin' AND g.rolname = o LOOP
    EXECUTE format('REVOKE %I FROM mr_admin GRANTED BY %I CASCADE', o, r.grantor);
  END LOOP;
  IF pg_has_role('mr_admin', o, 'MEMBER') THEN RAISE EXCEPTION 'mr_admin is still a member of % after close', o; END IF;
END $$;
\else
\echo 'r25-admin-window.sql: window must be open or close'
SELECT 1/0;
\endif
SELECT m.rolname AS member, g.rolname AS role, am.set_option, am.inherit_option, am.admin_option
  FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
 WHERE m.rolname = 'mr_admin';
SELECT :'window' AS deploy_window, pg_has_role('mr_admin', :'owner', 'MEMBER') AS admin_is_owner_member;
-- R26-P3-2 evidence: every member of the owner (must be empty after close).
SELECT :'window' AS deploy_window, coalesce(string_agg(m.rolname, ', ' ORDER BY m.rolname), '(none)') AS owner_members
  FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = :'owner');
