import os, openpyxl, psycopg2
from dotenv import load_dotenv
load_dotenv(override=True)

DB_HOST = os.getenv("CLOUD_DB_HOST")
DB_NAME = os.getenv("CLOUD_DB_NAME")
print(f"Connecting to: {DB_HOST} / {DB_NAME}")  # ← verify this is Supabase, not blank

conn = psycopg2.connect(
    host=DB_HOST, port=os.getenv("CLOUD_DB_PORT", "5432"),
    database=DB_NAME, user=os.getenv("CLOUD_DB_USER"),
    password=os.getenv("CLOUD_DB_PASSWORD"), sslmode="require",
)
cur = conn.cursor()

# Confirm the table exists before importing
cur.execute("SELECT to_regclass('public.consumer_masterlist')")
print("Table exists:", cur.fetchone()[0])

wb = openpyxl.load_workbook("MasterListConsumer.xlsx", read_only=True)
ws = wb["ConsumerMasterlist"]

batch = []
total = 0
for row in ws.iter_rows(min_row=2, values_only=True):
    acct_no, acct_name, meter_sn = row[0], row[1], row[2]
    if acct_no is None:
        continue
    batch.append((str(acct_no).strip(), (acct_name or "").strip(), (meter_sn or "").strip()))
    if len(batch) >= 5000:
        cur.executemany("""
            INSERT INTO consumer_masterlist (account_number, consumer_name, meter_number)
            VALUES (%s, %s, %s)
            ON CONFLICT (account_number) DO UPDATE
            SET consumer_name = EXCLUDED.consumer_name, meter_number = EXCLUDED.meter_number
        """, batch)
        conn.commit()
        total += len(batch)
        print(f"Imported {total} rows so far...")
        batch = []

if batch:
    cur.executemany("""
        INSERT INTO consumer_masterlist (account_number, consumer_name, meter_number)
        VALUES (%s, %s, %s)
        ON CONFLICT (account_number) DO UPDATE
        SET consumer_name = EXCLUDED.consumer_name, meter_number = EXCLUDED.meter_number
    """, batch)
    conn.commit()
    total += len(batch)

cur.execute("SELECT COUNT(*) FROM consumer_masterlist")
print(f"✅ Done. Total rows imported: {total}. Row count in table: {cur.fetchone()[0]}")

cur.close()
conn.close()