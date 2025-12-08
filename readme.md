# Cookie DB System (Single Table)

## Table

```sql
CREATE TABLE cookie_accounts (
    id          BIGSERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    pass_enc    TEXT NOT NULL,
    cookie_enc  TEXT NOT NULL,
    status      TEXT NOT NULL,
    vps_node    TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
