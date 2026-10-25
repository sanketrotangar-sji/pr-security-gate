create table if not exists webhook_deliveries (
  delivery_id text primary key,
  received_at timestamptz not null default now()
);

create index if not exists webhook_deliveries_received_at_idx
  on webhook_deliveries (received_at);

alter table webhook_deliveries enable row level security;
