import hashlib

from sqlalchemy import select

from app.core.auth_context import tenant_context
from app.core.database import AssetRow, session_scope, utcnow
from app.core.policy_enforcement import scan_policy


SURFACE_FIELDS = (
    "ips",
    "ports",
    "services",
    "technologies",
    "web_apps",
    "apis",
    "endpoints",
    "dns_records",
    "tls_protocol",
    "tls_not_after",
    "tls_expiry_days",
)


def _norm(values):
    """
    Normalize collection-like values into a sorted list of strings.

    Handles both iterables (lists/sets/tuples) and scalar values safely.
    This prevents TypeError when a scalar value such as an integer is passed.
    """
    if values is None:
        return []

    if isinstance(values, (list, tuple, set)):
        return sorted(
            {
                str(x)
                for x in values
                if x is not None
            }
        )

    return [str(values)]


def _normalize_tls_expiry_days(value):
    """
    Normalize TLS certificate expiry days to an integer or None.

    Supports:
    - int / float
    - numeric strings
    - legacy single-item lists/tuples/sets
    """
    if value is None:
        return None

    if isinstance(value, (list, tuple, set)):
        value = next(iter(value), None)

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _diff(old, current):
    changes = []

    for field in SURFACE_FIELDS:

        # TLS expiry is a scalar integer, not a collection.
        if field == "tls_expiry_days":
            before_value = _normalize_tls_expiry_days(old.get(field))
            after_value = _normalize_tls_expiry_days(current.get(field))

            before = (
                {before_value}
                if before_value is not None
                else set()
            )

            after = (
                {after_value}
                if after_value is not None
                else set()
            )

        # TLS expiration date is a scalar string.
        elif field == "tls_not_after":
            before_value = old.get(field)
            after_value = current.get(field)

            before = (
                {str(before_value)}
                if before_value
                else set()
            )

            after = (
                {str(after_value)}
                if after_value
                else set()
            )

        # All other surface fields are collection-like.
        else:
            before = set(
                _norm(old.get(field, []))
            )
            after = set(
                _norm(current.get(field, []))
            )

        added = sorted(after - before)
        removed = sorted(before - after)

        if added or removed:
            changes.append(
                {
                    "field": field,
                    "added": added,
                    "removed": removed,
                }
            )

    return changes


class AssetInventory:

    async def upsert(
        self,
        target,
        technologies=None,
        ports=None,
        endpoints=None,
        ips=None,
        services=None,
        web_apps=None,
        apis=None,
        finding_ids=None,
        snapshot=None,
    ):
        tid = tenant_context.get() or "legacy"

        canonical_identity = target.strip().lower()
        key = hashlib.sha256(
            f"{tid}:{canonical_identity}".encode()
        ).hexdigest()[:16]

        async with session_scope(tid) as db:
            row = await db.scalar(select(AssetRow).where(AssetRow.asset_id == key, AssetRow.tenant_id == tid))

            now = utcnow()

            old = (
                (row.data or {})
                if row
                else {}
            )

            def merged(name, values):
                return sorted(
                    set(old.get(name, []))
                    |
                    {
                        str(x)
                        for x in (values or [])
                        if x is not None
                    }
                )

            # ---------------------------------------------------------
            # Normalize surface snapshot
            # ---------------------------------------------------------
            snap = {}

            for key_name, value in (snapshot or {}).items():

                # TLS certificate expiry date is a scalar string.
                if key_name == "tls_not_after":
                    snap[key_name] = (
                        str(value)
                        if value
                        else None
                    )

                # TLS certificate expiry days is a scalar integer.
                elif key_name == "tls_expiry_days":
                    snap[key_name] = _normalize_tls_expiry_days(
                        value
                    )

                # All other snapshot fields are normalized collections.
                else:
                    snap[key_name] = _norm(value)

            # ---------------------------------------------------------
            # Detect surface changes
            # ---------------------------------------------------------
            previous = old.get("surface_snapshot") or {}

            changes = (
                []
                if not previous
                else _diff(previous, snap)
            )

            # ---------------------------------------------------------
            # TLS certificate expiry warning
            # ---------------------------------------------------------
            expiry = snap.get("tls_expiry_days")

            if expiry is not None and expiry <= 30:
                changes.append(
                    {
                        "field": "tls_expiry_days",
                        "added": [str(expiry)],
                        "removed": [],
                        "warning": (
                            "TLS certificate expires within 30 days"
                        ),
                    }
                )

            # ---------------------------------------------------------
            # Build asset data
            # ---------------------------------------------------------
            data = {
                **old,
                "asset_id": key,
                "target": target,
                "ips": merged("ips", ips),
                "ports": merged("ports", ports),
                "services": merged("services", services),
                "technologies": merged(
                    "technologies",
                    technologies,
                ),
                "web_apps": merged(
                    "web_apps",
                    web_apps,
                ),
                "apis": merged(
                    "apis",
                    apis,
                ),
                "endpoints": merged(
                    "endpoints",
                    endpoints,
                ),
                "finding_ids": merged(
                    "finding_ids",
                    finding_ids,
                ),
                "surface_snapshot": snap,
                "surface_changes": changes,
                "last_seen": now.isoformat(),
            }

            # ---------------------------------------------------------
            # Create new asset
            # ---------------------------------------------------------
            if row is None:
                limit = int(
                    scan_policy(tid)["max_assets"]
                )

                count = (
                    await db.scalar(
                        select(
                            __import__(
                                "sqlalchemy",
                                fromlist=["func"],
                            ).func.count()
                        )
                        .select_from(AssetRow)
                        .where(
                            AssetRow.tenant_id == tid
                        )
                    )
                    or 0
                )

                if int(count) >= limit:
                    raise ValueError(
                        "Tenant asset inventory limit reached"
                    )

                data["first_seen"] = now.isoformat()
                data["surface_baseline"] = True

                db.add(
                    AssetRow(
                        asset_id=key,
                        tenant_id=tid,
                        canonical_identity=canonical_identity,
                        target=target,
                        data=data,
                        first_seen=now,
                        last_seen=now,
                    )
                )

            # ---------------------------------------------------------
            # Update existing asset
            # ---------------------------------------------------------
            else:
                row.target = target
                row.canonical_identity = canonical_identity
                row.data = data
                row.last_seen = now

            return data

    async def get(self, asset_id):
        tid = tenant_context.get() or "legacy"

        async with session_scope(tid) as db:
            row = await db.scalar(
                select(AssetRow).where(
                    AssetRow.asset_id == asset_id,
                    AssetRow.tenant_id == tid,
                )
            )

            return row.data if row else None

    async def list(self):
        tid = tenant_context.get() or "legacy"

        async with session_scope(tid) as db:
            result = await db.execute(
                select(AssetRow)
                .where(
                    AssetRow.tenant_id == tid
                )
                .order_by(
                    AssetRow.last_seen.desc()
                )
                .limit(500)
            )
            rows = result.scalars().all()

            return [
                row.data
                for row in rows
            ]


inventory = AssetInventory()