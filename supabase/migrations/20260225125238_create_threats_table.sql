CREATE TABLE threats (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  detected_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  source_ip   TEXT NOT NULL,
  username    TEXT,
  threat_type TEXT NOT NULL,
  severity    TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  details     TEXT,
  status      TEXT NOT NULL DEFAULT 'OPEN' 
              CHECK (status IN ('OPEN','INVESTIGATING','CONTAINED','DISMISSED')),
  analyst     TEXT
);

CREATE INDEX idx_threats_detected_at ON threats (detected_at DESC);
CREATE INDEX idx_threats_status ON threats (status);

ALTER TABLE threats ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service full access"
ON threats FOR ALL
TO service_role
USING (true)
WITH CHECK (true);