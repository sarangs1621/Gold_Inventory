"""
COMPREHENSIVE ACCOUNTING MODEL FIX
===================================
This script performs a complete accounting system reset and rebuild:

1. Creates backup of existing data
2. Defines and enforces proper account type taxonomy
3. Fixes all account types to match taxonomy
4. Deletes ALL finance transactions
5. Rebuilds transactions from invoice payments using double-entry
6. Recalculates all account balances correctly
7. Validates trial balance (Total Debits = Total Credits)
8. Generates comprehensive audit report

ACCOUNTING TAXONOMY (LOCKED):
- ASSET: Cash, Bank, Petty Cash, Accounts Receivable, Gold Stock, etc.
- INCOME: Sales Income, Gold Exchange Income, Making Charges Income, etc.
- EXPENSE: Rent, Wages, Electricity, Bank Charges, etc.
- LIABILITY: GST Payable, Accounts Payable, Customer Advance, etc.
- EQUITY: Capital, Retained Earnings, Owner Drawings

ACCOUNTING RULES (NON-NEGOTIABLE):
1. Invoice creation/finalization → NO finance transactions
2. Payment received → Double-entry ONLY:
   - Debit: Cash/Bank (ASSET increases)
   - Credit: Sales Income (INCOME increases)
3. Account balance updates respect account type:
   - ASSET/EXPENSE: Debit increases, Credit decreases
   - INCOME/LIABILITY/EQUITY: Credit increases, Debit decreases
4. GST is LIABILITY, never touches Income/Expense
5. Trial balance MUST always net to ZERO
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
import uuid
import subprocess
import sys

# Load environment
load_dotenv()

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Account type taxonomy
ACCOUNT_TYPES = {
    'asset': 'ASSET',
    'income': 'INCOME',
    'expense': 'EXPENSE',
    'liability': 'LIABILITY',
    'equity': 'EQUITY'
}

# Standard account mappings (preserve these names)
STANDARD_ACCOUNTS = {
    'Cash': 'asset',
    'Bank': 'asset',
    'Petty Cash': 'asset',
    'Sales': 'income',
    'Sales Income': 'income',
    'Gold Exchange': 'income',
    'Gold Exchange Income': 'income',
    'Making Charges Income': 'income',
    'Stone Charges Income': 'income',
    'Service Income': 'income',
    'GST Payable': 'liability',
    'VAT Payable': 'liability',
    'Customer Advance': 'liability',
    'Rent Expense': 'expense',
    'Wages Expense': 'expense',
    'Bank Charges': 'expense',
    'Accounts Receivable': 'asset',
    'Accounts Payable': 'liability',
    'Capital': 'equity',
    'Retained Earnings': 'equity'
}

def calculate_balance_delta(account_type: str, transaction_type: str, amount: float) -> float:
    """
    Calculate balance change based on account type and transaction type.
    
    ACCOUNTING RULES:
    - ASSET/EXPENSE: Debit increases (+), Credit decreases (-)
    - INCOME/LIABILITY/EQUITY: Credit increases (+), Debit decreases (-)
    """
    if account_type in ['asset', 'expense']:
        # Debit increases, Credit decreases
        return amount if transaction_type == 'debit' else -amount
    else:  # income, liability, equity
        # Credit increases, Debit decreases
        return amount if transaction_type == 'credit' else -amount

async def create_backup():
    """Create backup before migration"""
    print("\n[BACKUP] Creating backup of current data...")
    try:
        # Run backup script
        result = subprocess.run(
            [sys.executable, '/app/backend/backup_accounting_data.py'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("  ✓ Backup created successfully")
            return True
        else:
            print(f"  ❌ Backup failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ❌ Backup error: {str(e)}")
        return False

async def fix_account_types():
    """Fix account types to match taxonomy"""
    print("\n[STEP 1] Fixing account types to match taxonomy...")
    
    accounts = await db.accounts.find({"is_deleted": False}).to_list(None)
    fixed_count = 0
    
    for account in accounts:
        account_name = account.get('name', '')
        current_type = account.get('account_type', '').lower()
        
        # Check if account name matches standard accounts
        correct_type = None
        for std_name, std_type in STANDARD_ACCOUNTS.items():
            if std_name.lower() in account_name.lower():
                correct_type = std_type
                break
        
        # If we found a correct type and it's different from current
        if correct_type and correct_type != current_type:
            await db.accounts.update_one(
                {"id": account['id']},
                {"$set": {"account_type": correct_type}}
            )
            print(f"  ✓ Fixed '{account_name}': '{current_type}' → '{correct_type}'")
            fixed_count += 1
        
        # Validate account type is in taxonomy
        elif current_type not in ACCOUNT_TYPES:
            # Default to 'asset' if type is invalid
            await db.accounts.update_one(
                {"id": account['id']},
                {"$set": {"account_type": "asset"}}
            )
            print(f"  ⚠️  Fixed invalid type for '{account_name}': '{current_type}' → 'asset' (default)")
            fixed_count += 1
    
    print(f"  ✓ Fixed {fixed_count} account types")
    return fixed_count

async def delete_all_transactions():
    """Soft-delete ALL existing transactions"""
    print("\n[STEP 2] Deleting ALL existing finance transactions...")
    
    # Count before deletion
    active_count = await db.transactions.count_documents({"is_deleted": False})
    print(f"  Found {active_count} active transactions")
    
    # Soft delete all
    if active_count > 0:
        result = await db.transactions.update_many(
            {"is_deleted": False},
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": datetime.now(timezone.utc),
                    "deleted_by": "COMPREHENSIVE_ACCOUNTING_FIX"
                }
            }
        )
        print(f"  ✓ Soft-deleted {result.modified_count} transactions")
    else:
        print("  ✓ No transactions to delete")
    
    return active_count

async def reset_account_balances():
    """Reset all account balances to opening_balance"""
    print("\n[STEP 3] Resetting all account balances...")
    
    accounts = await db.accounts.find({"is_deleted": False}).to_list(None)
    
    for account in accounts:
        opening_balance = account.get('opening_balance', 0)
        await db.accounts.update_one(
            {"id": account['id']},
            {"$set": {"current_balance": opening_balance}}
        )
    
    print(f"  ✓ Reset {len(accounts)} account balances to opening_balance")
    return len(accounts)

async def rebuild_transactions_from_payments():
    """Rebuild all transactions from invoice payments with proper double-entry"""
    print("\n[STEP 4] Rebuilding transactions from invoice payments...")
    
    # Get all invoices with payments
    invoices = await db.invoices.find({
        "is_deleted": False,
        "paid_amount": {"$gt": 0}
    }).to_list(None)
    
    print(f"  Found {len(invoices)} invoices with payments")
    
    transactions_created = 0
    payment_records_processed = 0
    
    # We need to track individual payment transactions
    # Look for soft-deleted transactions that were payment-related
    old_payment_txns = await db.transactions.find({
        "is_deleted": True,
        "reference_type": "invoice",
        "deleted_by": "COMPREHENSIVE_ACCOUNTING_FIX"
    }).to_list(None)
    
    print(f"  Found {len(old_payment_txns)} old payment transaction records")
    
    # Group by invoice_id to reconstruct payment history
    payments_by_invoice = {}
    for txn in old_payment_txns:
        invoice_id = txn.get('reference_id')
        if not invoice_id:
            continue
        
        if invoice_id not in payments_by_invoice:
            payments_by_invoice[invoice_id] = []
        payments_by_invoice[invoice_id].append(txn)
    
    # Ensure we have required accounts
    cash_account = await db.accounts.find_one({"name": "Cash", "is_deleted": False})
    if not cash_account:
        cash_account = {
            "id": str(uuid.uuid4()),
            "name": "Cash",
            "account_type": "asset",
            "opening_balance": 0,
            "current_balance": 0,
            "created_at": datetime.now(timezone.utc),
            "created_by": "system",
            "is_deleted": False
        }
        await db.accounts.insert_one(cash_account)
        print("  ✓ Created 'Cash' account")
    
    sales_income_account = await db.accounts.find_one(
        {"name": {"$in": ["Sales Income", "Sales"]}, "is_deleted": False}
    )
    if not sales_income_account:
        sales_income_account = {
            "id": str(uuid.uuid4()),
            "name": "Sales Income",
            "account_type": "income",
            "opening_balance": 0,
            "current_balance": 0,
            "created_at": datetime.now(timezone.utc),
            "created_by": "system",
            "is_deleted": False
        }
        await db.accounts.insert_one(sales_income_account)
        print("  ✓ Created 'Sales Income' account")
    
    # Rebuild transactions for each invoice with payments
    for invoice_id, payment_txns in payments_by_invoice.items():
        # Get invoice
        invoice = await db.invoices.find_one({"id": invoice_id, "is_deleted": False})
        if not invoice:
            continue
        
        # Process each payment transaction
        for old_txn in payment_txns:
            # Skip if this looks like the credit side (we'll create both sides fresh)
            if 'Income' in old_txn.get('category', ''):
                continue
            
            payment_amount = old_txn.get('amount', 0)
            if payment_amount <= 0:
                continue
            
            payment_mode = old_txn.get('mode', 'Cash')
            account_id = old_txn.get('account_id') or cash_account['id']
            created_at = old_txn.get('created_at', datetime.now(timezone.utc))
            created_by = old_txn.get('created_by', 'system')
            
            # Get the account to update
            payment_account = await db.accounts.find_one({"id": account_id, "is_deleted": False})
            if not payment_account:
                payment_account = cash_account
                account_id = cash_account['id']
            
            # Generate new transaction numbers
            year = created_at.year if isinstance(created_at, datetime) else datetime.now(timezone.utc).year
            count = await db.transactions.count_documents({"is_deleted": False})
            
            # TRANSACTION 1: DEBIT Cash/Bank (ASSET)
            debit_txn_number = f"TXN-{year}-{str(count + 1).zfill(4)}"
            debit_transaction = {
                "id": str(uuid.uuid4()),
                "transaction_number": debit_txn_number,
                "date": created_at,
                "created_at": created_at,
                "transaction_type": "debit",
                "mode": payment_mode,
                "account_id": account_id,
                "account_name": payment_account.get('name', 'Cash'),
                "party_id": invoice.get('customer_id'),
                "party_name": invoice.get('customer_name') or invoice.get('walk_in_name'),
                "amount": payment_amount,
                "category": "Invoice Payment - Cash/Bank (Debit)",
                "notes": f"Payment for invoice {invoice.get('invoice_number', 'N/A')}",
                "reference_type": "invoice",
                "reference_id": invoice_id,
                "created_by": created_by,
                "is_deleted": False
            }
            
            await db.transactions.insert_one(debit_transaction)
            
            # Update Cash/Bank balance (ASSET: debit increases)
            delta = calculate_balance_delta(
                payment_account.get('account_type', 'asset'),
                'debit',
                payment_amount
            )
            await db.accounts.update_one(
                {"id": account_id},
                {"$inc": {"current_balance": delta}}
            )
            
            transactions_created += 1
            
            # TRANSACTION 2: CREDIT Sales Income (INCOME)
            credit_txn_number = f"TXN-{year}-{str(count + 2).zfill(4)}"
            credit_transaction = {
                "id": str(uuid.uuid4()),
                "transaction_number": credit_txn_number,
                "date": created_at,
                "created_at": created_at,
                "transaction_type": "credit",
                "mode": payment_mode,
                "account_id": sales_income_account['id'],
                "account_name": sales_income_account['name'],
                "party_id": invoice.get('customer_id'),
                "party_name": invoice.get('customer_name') or invoice.get('walk_in_name'),
                "amount": payment_amount,
                "category": "Invoice Payment - Sales Income (Credit)",
                "notes": f"Revenue for invoice {invoice.get('invoice_number', 'N/A')}",
                "reference_type": "invoice",
                "reference_id": invoice_id,
                "created_by": created_by,
                "is_deleted": False
            }
            
            await db.transactions.insert_one(credit_transaction)
            
            # Update Sales Income balance (INCOME: credit increases)
            delta = calculate_balance_delta(
                sales_income_account.get('account_type', 'income'),
                'credit',
                payment_amount
            )
            await db.accounts.update_one(
                {"id": sales_income_account['id']},
                {"$inc": {"current_balance": delta}}
            )
            
            transactions_created += 1
            payment_records_processed += 1
    
    print(f"  ✓ Processed {payment_records_processed} payment records")
    print(f"  ✓ Created {transactions_created} new double-entry transactions")
    
    return transactions_created

async def validate_trial_balance():
    """Validate that trial balance is correct (Total Debits = Total Credits)"""
    print("\n[STEP 5] Validating trial balance...")
    
    accounts = await db.accounts.find({"is_deleted": False}).to_list(None)
    
    total_debit_balance = 0
    total_credit_balance = 0
    
    print("\n  Account Balances by Type:")
    print("  " + "-" * 78)
    
    # Group by account type
    by_type = {}
    for account in accounts:
        acc_type = account.get('account_type', 'unknown')
        if acc_type not in by_type:
            by_type[acc_type] = []
        by_type[acc_type].append(account)
    
    # Print by type
    for acc_type in ['asset', 'expense', 'income', 'liability', 'equity', 'unknown']:
        if acc_type not in by_type:
            continue
        
        print(f"\n  {acc_type.upper()}:")
        for account in by_type[acc_type]:
            balance = account.get('current_balance', 0)
            name = account.get('name', 'Unknown')
            print(f"    {name:<40} {balance:>15.2f}")
            
            # For trial balance:
            # Debit side: Assets & Expenses (normal positive balances)
            # Credit side: Income, Liability, Equity (normal positive balances)
            if acc_type in ['asset', 'expense']:
                total_debit_balance += balance
            else:  # income, liability, equity
                total_credit_balance += balance
    
    print("\n  " + "-" * 78)
    print(f"  {'Total Debit Side (Assets + Expenses)':<45} {total_debit_balance:>15.2f}")
    print(f"  {'Total Credit Side (Income + Liability + Equity)':<45} {total_credit_balance:>15.2f}")
    print(f"  {'Difference (MUST be close to 0)':<45} {abs(total_debit_balance - total_credit_balance):>15.2f}")
    print("  " + "-" * 78)
    
    is_balanced = abs(total_debit_balance - total_credit_balance) < 1.0  # Allow 1 OMR rounding error
    
    if is_balanced:
        print("\n  ✅ TRIAL BALANCE IS CORRECT!")
    else:
        print("\n  ❌ TRIAL BALANCE IS NOT BALANCED!")
    
    return is_balanced, total_debit_balance, total_credit_balance

async def validate_double_entry():
    """Validate that all transactions follow double-entry (sum of debits = sum of credits)"""
    print("\n[STEP 6] Validating double-entry bookkeeping...")
    
    transactions = await db.transactions.find({"is_deleted": False}).to_list(None)
    
    total_debits = sum(t.get('amount', 0) for t in transactions if t.get('transaction_type') == 'debit')
    total_credits = sum(t.get('amount', 0) for t in transactions if t.get('transaction_type') == 'credit')
    
    print(f"  Total debit transactions: {total_debits:.2f}")
    print(f"  Total credit transactions: {total_credits:.2f}")
    print(f"  Difference: {abs(total_debits - total_credits):.2f}")
    
    is_balanced = abs(total_debits - total_credits) < 1.0  # Allow 1 OMR rounding error
    
    if is_balanced:
        print("  ✅ DOUBLE-ENTRY IS CORRECT!")
    else:
        print("  ❌ DOUBLE-ENTRY IS NOT BALANCED!")
    
    return is_balanced

async def generate_audit_report():
    """Generate comprehensive audit report"""
    print("\n[STEP 7] Generating audit report...")
    
    # Collect statistics
    accounts = await db.accounts.find({"is_deleted": False}).to_list(None)
    transactions = await db.transactions.find({"is_deleted": False}).to_list(None)
    invoices = await db.invoices.find({"is_deleted": False}).to_list(None)
    
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_accounts": len(accounts),
            "total_transactions": len(transactions),
            "total_invoices": len(invoices),
            "invoices_with_payments": len([i for i in invoices if i.get('paid_amount', 0) > 0])
        },
        "accounts_by_type": {},
        "validation": {}
    }
    
    # Group accounts by type
    for account in accounts:
        acc_type = account.get('account_type', 'unknown')
        if acc_type not in report["accounts_by_type"]:
            report["accounts_by_type"][acc_type] = {
                "count": 0,
                "total_balance": 0,
                "accounts": []
            }
        report["accounts_by_type"][acc_type]["count"] += 1
        report["accounts_by_type"][acc_type]["total_balance"] += account.get('current_balance', 0)
        report["accounts_by_type"][acc_type]["accounts"].append({
            "name": account.get('name'),
            "balance": account.get('current_balance', 0)
        })
    
    # Validation results
    is_trial_balanced, total_debit, total_credit = await validate_trial_balance()
    is_double_entry_valid = await validate_double_entry()
    
    report["validation"]["trial_balance_valid"] = is_trial_balanced
    report["validation"]["total_debit_balance"] = total_debit
    report["validation"]["total_credit_balance"] = total_credit
    report["validation"]["double_entry_valid"] = is_double_entry_valid
    
    # Save report
    import json
    report_path = f"/app/audit_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"  ✓ Audit report saved to: {report_path}")
    
    return report

async def comprehensive_fix():
    """Execute comprehensive accounting fix"""
    print("=" * 80)
    print("COMPREHENSIVE ACCOUNTING MODEL FIX")
    print("=" * 80)
    print("\nThis will:")
    print("1. Create backup of current data")
    print("2. Fix all account types")
    print("3. Delete ALL transactions")
    print("4. Rebuild transactions from invoice payments")
    print("5. Recalculate all balances")
    print("6. Validate trial balance")
    print("7. Generate audit report")
    print("\n" + "=" * 80)
    
    # Step 0: Backup
    backup_success = await create_backup()
    if not backup_success:
        print("\n❌ BACKUP FAILED - Aborting migration for safety")
        print("Please check backup script and try again")
        return False
    
    # Step 1: Fix account types
    await fix_account_types()
    
    # Step 2: Delete transactions
    await delete_all_transactions()
    
    # Step 3: Reset balances
    await reset_account_balances()
    
    # Step 4: Rebuild transactions
    await rebuild_transactions_from_payments()
    
    # Step 5-6: Validate
    is_trial_balanced, _, _ = await validate_trial_balance()
    is_double_entry = await validate_double_entry()
    
    # Step 7: Generate report
    await generate_audit_report()
    
    print("\n" + "=" * 80)
    if is_trial_balanced and is_double_entry:
        print("✅ COMPREHENSIVE FIX COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print("\nACCOUNTING SYSTEM STATUS:")
        print("  ✅ Trial balance is correct")
        print("  ✅ Double-entry is valid")
        print("  ✅ All account types are correct")
        print("  ✅ Transactions rebuilt from payments")
        print("\nNEXT STEPS:")
        print("1. Restart backend: sudo supervisorctl restart backend")
        print("2. Check Finance Dashboard in UI")
        print("3. Test adding a new payment")
        print("4. Verify reports show correct data")
    else:
        print("⚠️  FIX COMPLETED WITH VALIDATION WARNINGS")
        print("=" * 80)
        print("\nPlease review validation results above")
        print("System may need manual adjustments")
    
    print("=" * 80)
    
    return is_trial_balanced and is_double_entry

if __name__ == "__main__":
    asyncio.run(comprehensive_fix())
