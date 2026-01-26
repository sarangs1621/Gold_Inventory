"""
ACCOUNTING DATA RESTORE SCRIPT
===============================
Restores accounting data from a backup file.
USE WITH CAUTION - This will overwrite current data!

Usage:
    python restore_accounting_data.py /app/backup/accounting_backup_TIMESTAMP.json
"""

import asyncio
import json
import sys
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
from pathlib import Path

# Load environment
load_dotenv()

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

async def restore_accounting_data(backup_file_path: str):
    """Restore accounting data from backup file"""
    
    print("=" * 80)
    print("ACCOUNTING DATA RESTORE - STARTING")
    print("=" * 80)
    print(f"\n⚠️  WARNING: This will OVERWRITE current accounting data!")
    print(f"Restoring from: {backup_file_path}\n")
    
    # Load backup file
    backup_path = Path(backup_file_path)
    if not backup_path.exists():
        print(f"❌ ERROR: Backup file not found: {backup_file_path}")
        return False
    
    print("Loading backup file...")
    with open(backup_path, 'r') as f:
        backup_data = json.load(f)
    
    print(f"  ✓ Backup loaded: {backup_data.get('backup_timestamp')}")
    
    collections = backup_data.get('collections', {})
    
    # Restore accounts
    print("\n[1/5] Restoring accounts...")
    if 'accounts' in collections:
        await db.accounts.delete_many({})  # Clear existing
        if collections['accounts']:
            await db.accounts.insert_many(collections['accounts'])
        print(f"  ✓ Restored {len(collections['accounts'])} accounts")
    
    # Restore transactions
    print("[2/5] Restoring transactions...")
    if 'transactions' in collections:
        await db.transactions.delete_many({})  # Clear existing
        if collections['transactions']:
            await db.transactions.insert_many(collections['transactions'])
        print(f"  ✓ Restored {len(collections['transactions'])} transactions")
    
    # Restore invoices
    print("[3/5] Restoring invoices...")
    if 'invoices' in collections:
        await db.invoices.delete_many({})  # Clear existing
        if collections['invoices']:
            await db.invoices.insert_many(collections['invoices'])
        print(f"  ✓ Restored {len(collections['invoices'])} invoices")
    
    # Restore daily closings
    print("[4/5] Restoring daily closings...")
    if 'daily_closings' in collections:
        await db.daily_closings.delete_many({})  # Clear existing
        if collections['daily_closings']:
            await db.daily_closings.insert_many(collections['daily_closings'])
        print(f"  ✓ Restored {len(collections['daily_closings'])} daily closings")
    
    # Restore gold ledger
    print("[5/5] Restoring gold ledger...")
    if 'gold_ledger' in collections:
        await db.gold_ledger.delete_many({})  # Clear existing
        if collections['gold_ledger']:
            await db.gold_ledger.insert_many(collections['gold_ledger'])
        print(f"  ✓ Restored {len(collections['gold_ledger'])} gold ledger entries")
    
    print("\n" + "=" * 80)
    print("RESTORE COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print("\nOriginal backup statistics:")
    stats = backup_data.get('statistics', {})
    for key, value in stats.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    print("=" * 80)
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python restore_accounting_data.py <backup_file_path>")
        sys.exit(1)
    
    backup_file = sys.argv[1]
    success = asyncio.run(restore_accounting_data(backup_file))
    
    if not success:
        sys.exit(1)
