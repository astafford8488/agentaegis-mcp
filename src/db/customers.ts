import { getDb } from "./client.js";
import type { Customer } from "./types.js";

export async function findCustomerByEmail(email: string): Promise<Customer | null> {
  const { data, error } = await getDb()
    .from("aegis_customers")
    .select("*")
    .eq("email", email)
    .maybeSingle();

  if (error) throw error;
  return data;
}

export async function findCustomerByWallet(wallet: string): Promise<Customer | null> {
  const { data, error } = await getDb()
    .from("aegis_customers")
    .select("*")
    .eq("wallet_address", wallet)
    .maybeSingle();

  if (error) throw error;
  return data;
}

export async function createCustomer(input: {
  email: string;
  name?: string;
  company?: string;
  wallet_address?: string;
}): Promise<Customer> {
  const { data, error } = await getDb()
    .from("aegis_customers")
    .insert({
      email: input.email,
      name: input.name || null,
      company: input.company || null,
      wallet_address: input.wallet_address || null,
    })
    .select()
    .single();

  if (error) throw error;
  return data;
}

export async function deductBalance(customerId: string, amount: number): Promise<boolean> {
  const { data: customer, error: fetchError } = await getDb()
    .from("aegis_customers")
    .select("prepaid_balance_usd")
    .eq("id", customerId)
    .single();

  if (fetchError || !customer) return false;
  if (customer.prepaid_balance_usd < amount) return false;

  const { error } = await getDb()
    .from("aegis_customers")
    .update({ prepaid_balance_usd: customer.prepaid_balance_usd - amount })
    .eq("id", customerId);

  return !error;
}

export async function addBalance(customerId: string, amount: number): Promise<void> {
  const { data: customer } = await getDb()
    .from("aegis_customers")
    .select("prepaid_balance_usd")
    .eq("id", customerId)
    .single();

  if (!customer) throw new Error("Customer not found");

  await getDb()
    .from("aegis_customers")
    .update({ prepaid_balance_usd: customer.prepaid_balance_usd + amount })
    .eq("id", customerId);
}
