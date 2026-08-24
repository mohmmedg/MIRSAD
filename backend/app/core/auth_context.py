from contextvars import ContextVar
tenant_context: ContextVar[str|None] = ContextVar('tenant_context',default=None)
