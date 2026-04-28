-- PSD Procurement Tracker — auth-only RLS policies.
--
-- Run this script ONCE in the Supabase SQL editor for project
-- wrcbqdwgpapmykqjnvny after enabling email/password auth.
--
-- It locks the three application tables down so that ONLY signed-in
-- (authenticated) users can read or write. Anonymous access is removed.
--
-- Steps in the Supabase dashboard before running:
--   1. Authentication > Providers > Email: enable.
--   2. Authentication > Settings: optionally disable "Confirm email"
--      if you want new sign-ups to log in immediately. Otherwise users
--      will receive a confirmation link first.
--   3. Authentication > Users: create accounts manually here, OR let
--      users self-register through the app's "Create account" button.

-- 1. Enable RLS -------------------------------------------------------
ALTER TABLE public.app_settings  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rfq_requests  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rfq_items     ENABLE ROW LEVEL SECURITY;

-- 2. Drop any pre-existing public/anon policies -----------------------
--    (Adjust names to match anything previously defined in your project.)
DO $$
DECLARE
  pol record;
BEGIN
  FOR pol IN
    SELECT policyname, tablename
    FROM   pg_policies
    WHERE  schemaname = 'public'
      AND  tablename  IN ('app_settings', 'rfq_requests', 'rfq_items')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I',
                   pol.policyname, pol.tablename);
  END LOOP;
END $$;

-- 3. Authenticated-only full access -----------------------------------
CREATE POLICY "auth_rw_app_settings"
  ON public.app_settings
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "auth_rw_rfq_requests"
  ON public.rfq_requests
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

CREATE POLICY "auth_rw_rfq_items"
  ON public.rfq_items
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- 4. Revoke anon role privileges to be safe ---------------------------
REVOKE ALL ON public.app_settings  FROM anon;
REVOKE ALL ON public.rfq_requests  FROM anon;
REVOKE ALL ON public.rfq_items     FROM anon;

GRANT  SELECT, INSERT, UPDATE, DELETE ON public.app_settings  TO authenticated;
GRANT  SELECT, INSERT, UPDATE, DELETE ON public.rfq_requests  TO authenticated;
GRANT  SELECT, INSERT, UPDATE, DELETE ON public.rfq_items     TO authenticated;
