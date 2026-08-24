import os
os.environ.setdefault('AUTH_JWT_SECRET','unit-test-secret-that-is-long-enough-32')
from app.core.auth import hash_password, verify_password, ROLE_RANK

def test_password_hashing():
    h=hash_password('correct horse battery staple')
    assert h.startswith('scrypt$') and h != 'correct horse battery staple'
    assert verify_password('correct horse battery staple',h)
    assert not verify_password('wrong password',h)

def test_rbac_order():
    assert ROLE_RANK['viewer'] < ROLE_RANK['analyst'] < ROLE_RANK['admin']
