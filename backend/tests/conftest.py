"""Test-wide settings: the suite logs in as admin, so give the fresh app an administrator password."""
import os

os.environ.setdefault("ADMIN_PASSWORD", "Eolwatch!2026")
os.environ.setdefault("JWT_SECRET", "test-only-signing-secret-not-for-deployment")
os.environ.setdefault("VERIFICATION_BUDGET_SECONDS", "0")   # no tracker/kernel.org lookups after imports in tests
