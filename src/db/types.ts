export interface Customer {
  id: string;
  email: string;
  name: string | null;
  company: string | null;
  wallet_address: string | null;
  stripe_customer_id: string | null;
  prepaid_balance_usd: number;
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
}

export interface APIKey {
  id: string;
  customer_id: string;
  key_hash: string;
  key_prefix: string;
  name: string;
  monthly_limit_usd: number;
  current_month_usage_usd: number;
  last_used_at: string | null;
  created_at: string;
  revoked_at: string | null;
  metadata: Record<string, unknown>;
}

export interface ScanJob {
  id: string;
  customer_id: string | null;
  api_key_id: string | null;
  tool_name: string;
  target: string;
  input_params: Record<string, unknown>;
  status: "queued" | "running" | "completed" | "failed" | "timeout";
  result: Record<string, unknown> | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  created_at: string;
}

export interface UsageLogEntry {
  id: string;
  customer_id: string | null;
  api_key_id: string | null;
  tool_name: string;
  target: string | null;
  price_usd: number;
  paid_via: "api_key_balance" | "x402" | "stripe" | "free_tier" | "admin_credit";
  payment_ref: string | null;
  success: boolean;
  error_message: string | null;
  request_ip: string | null;
  user_agent: string | null;
  created_at: string;
}

export interface Webhook {
  id: string;
  customer_id: string;
  url: string;
  secret: string;
  events_subscribed: string[];
  active: boolean;
  last_delivery_at: string | null;
  last_delivery_status: number | null;
  failure_count: number;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  response_status: number | null;
  response_body: string | null;
  attempts: number;
  next_retry_at: string | null;
  delivered_at: string | null;
  created_at: string;
}
