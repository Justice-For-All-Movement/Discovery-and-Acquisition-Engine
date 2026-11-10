import type { Migration } from '../service-kit.ts';

export const SCHEMA = 'e04_discovery';

const scope = 'tenant_id text not null, project_id text not null';
export const migrations: readonly Migration[] = [
  { id: '001_core', sql: `
create table {s}.sources (
  ${scope}, id uuid primary key, name text not null, kind text not null, base_url text not null, config jsonb not null,
  access_terms text not null, reuse text not null, rate_limit jsonb not null, refresh_policy jsonb not null,
  robots_policy text not null default 'honour' check (robots_policy in ('honour','ignore')),
  permission_refs text[] not null default '{}', compartment text, credential jsonb,
  blocked boolean not null default false, stale boolean not null default false, reasons jsonb not null default '[]',
  revision int not null default 1, next_refresh_at timestamptz, last_refresh_at timestamptz,
  created_by text not null, created_at timestamptz not null, updated_at timestamptz not null,
  unique (tenant_id, project_id, name)
);
create table {s}.source_revisions (
  ${scope}, source_id uuid not null, revision int not null, snapshot jsonb not null, summary text not null,
  actor_id text not null, at timestamptz not null, primary key (source_id, revision)
);
create table {s}.runs (
  ${scope}, id uuid primary key, source_id uuid not null, kind text not null, state text not null, level text not null,
  options jsonb not null, checkpoint jsonb not null, job_id uuid, question_ref text, compartment text,
  error text, summary jsonb, created_by text not null, created_at timestamptz not null,
  started_at timestamptz, finished_at timestamptz, updated_at timestamptz not null
);
create index runs_source on {s}.runs (tenant_id, project_id, source_id, created_at);
create table {s}.receipts (
  ${scope}, id uuid primary key, kind text not null, purpose text not null, source_id uuid, run_id uuid, item_id uuid,
  request_url text, final_url text, redirect_chain jsonb not null, resolved_ip text, status int, headers jsonb not null,
  sha256 text, size bigint, media_type text, declared_media_type text, outcome text not null, message text not null,
  robots jsonb not null, conditional jsonb, storage jsonb not null, reuse text not null, credential_used boolean not null default false,
  tool jsonb not null, started_at timestamptz not null, finished_at timestamptz not null, compartment text, receipt_hash text not null
);
create index receipts_run on {s}.receipts (tenant_id, project_id, run_id);
create function {s}.receipts_immutable() returns trigger language plpgsql as $fn$ begin raise exception 'acquisition receipts are immutable'; end $fn$;
create trigger receipts_no_change before update or delete on {s}.receipts for each row execute function {s}.receipts_immutable();
create table {s}.run_pages (
  ${scope}, run_id uuid not null, seq int not null, url text not null, receipt_id uuid, outcome text not null,
  item_count int not null default 0, new_item_count int not null default 0, at timestamptz not null, primary key (run_id, seq)
);
create table {s}.items (
  ${scope}, id uuid primary key, source_id uuid not null, url text not null, canonical_url text not null, title text,
  listing jsonb not null default '{}', state text not null default 'discovered', last_outcome text,
  first_run_id uuid, discovered_at timestamptz not null, last_seen_at timestamptz not null, last_seen_run uuid, missing_since timestamptz,
  current_acquisition uuid, etag text, last_modified text, family_id uuid, question_ref text,
  blocked boolean not null default false, stale boolean not null default false, reasons jsonb not null default '[]', compartment text,
  unique (tenant_id, project_id, source_id, canonical_url)
);
create index items_canonical on {s}.items (tenant_id, project_id, canonical_url);
create table {s}.run_items (
  ${scope}, run_id uuid not null, item_id uuid not null, seq bigint generated always as identity, page_seq int,
  seen boolean not null default true, is_new boolean not null default false, outcome text not null default 'pending', detail text,
  acquisition_id uuid, receipt_id uuid, duplicate boolean not null default false, at timestamptz, primary key (run_id, item_id)
);
create index run_items_pending on {s}.run_items (run_id, outcome, seq);
create table {s}.families (
  ${scope}, id uuid primary key, sha256 text not null, size bigint not null, media_type text not null,
  source_family uuid not null, sketch integer[], created_at timestamptz not null, unique (tenant_id, project_id, sha256)
);
create index families_sketch on {s}.families using gin (sketch);
create table {s}.mirror_hints (
  ${scope}, id uuid primary key, family_id uuid not null, other_family_id uuid not null, relation text not null,
  method text not null, similarity real, at timestamptz not null
);
create table {s}.acquisitions (
  ${scope}, id uuid primary key, item_id uuid not null, source_id uuid not null, run_id uuid, revision int not null, level text not null check (level in ('metadata','bytes')),
  sha256 text not null, size bigint not null, media_type text not null, storage text not null, evidence_ref text, object_key text,
  family_id uuid, reuse text not null, access_terms text not null, receipt_id uuid not null, metadata jsonb not null, origin jsonb not null,
  changed boolean not null default false, supersedes uuid, compartment text, blocked boolean not null default false, reasons jsonb not null default '[]',
  acquired_at timestamptz not null, unique (item_id, revision)
);
create index acquisitions_family on {s}.acquisitions (tenant_id, project_id, family_id);
create table {s}.failures (
  ${scope}, id uuid primary key, item_id uuid not null unique, source_id uuid not null, run_id uuid, reason text not null, detail text not null,
  attempts int not null, next_retry_at timestamptz, last_receipt_id uuid, state text not null check (state in ('open','resolved','exhausted')),
  level text not null default 'bytes', first_at timestamptz not null, last_at timestamptz not null
);
create index failures_due on {s}.failures (state, next_retry_at);
create table {s}.gaps (
  ${scope}, id uuid primary key, source_id uuid not null, run_id uuid, item_id uuid, kind text not null, expected text not null, detail text not null,
  state text not null default 'open' check (state in ('open','resolved')), receipt_id uuid, compartment text,
  created_at timestamptz not null, resolved_at timestamptz, resolution text
);
create unique index gaps_open on {s}.gaps (tenant_id, project_id, source_id, kind, md5(expected)) where state = 'open';
create table {s}.search_attempts (
  ${scope}, id uuid primary key, source_id uuid not null, run_id uuid not null, question_ref text, query text not null, params jsonb not null,
  request_url text not null, state text not null, result_count int, total_reported int, error text, compartment text,
  created_by text not null, created_at timestamptz not null, finished_at timestamptz
);
create table {s}.leads (
  ${scope}, id uuid primary key, dedupe_key text not null, person_name text, role text, organization text,
  why text not null, question_ref text, source_item_ref text, origin text not null, extractor text, confidence_note text not null,
  identity_state text not null default 'unconfirmed', identity_note text, knowledge_state text not null default 'unverified',
  stale boolean not null default false, blocked boolean not null default false, reasons jsonb not null default '[]', compartment text,
  created_by text not null, created_at timestamptz not null, updated_at timestamptz not null, unique (tenant_id, project_id, dedupe_key)
);
create table {s}.lead_routes (
  ${scope}, id uuid primary key, lead_id uuid not null, kind text not null, value text not null,
  provenance_ref text, provenance_url text, provenance_note text,
  verification_state text not null default 'unverified', verification_note text, verified_at timestamptz, verified_by text,
  created_at timestamptz not null, unique (lead_id, kind, value)
);
create table {s}.robots_cache (
  ${scope}, origin text not null, fetched_at timestamptz not null, expires_at timestamptz not null, status int, outcome text not null,
  body text not null, primary key (tenant_id, project_id, origin)
);
-- Politeness state is deliberately shared by every tenant and worker: it holds host names and timestamps only.
create table {s}.host_rate (host text primary key, next_at timestamptz not null);
create table {s}.host_leases (id uuid primary key, host text not null, expires_at timestamptz not null);
create index host_leases_host on {s}.host_leases (host);
create table {s}.upstream_changes (
  ${scope}, event_id text not null, kind text not null, affected jsonb not null, at timestamptz not null, primary key (tenant_id, project_id, event_id)
);
` },
];
