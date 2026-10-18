"""
l2_cache.py
===========
SuperGhidra Persistent WAL-mode L2 SQLite Cache.

Provides high-performance, disk-backed caching with sub-millisecond local lookups.
Caches decompile, vtable, disassemble, and symbol queries to bypass JVM/Ghidra native
decompiler subprocesses entirely on cache hits.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("pyghidra_mcp.l2_cache")

DEFAULT_L2_CACHE_FILENAME = "ghidra_l2_cache.db"


class L2SQLiteCache:
    """
    Persistent WAL-mode SQLite cache for sub-millisecond local responses.
    Caches decompile, vtable, disassemble, refs, adrp_add, and opcodes queries.
    Enables instant lookups with 0% JVM CPU overhead.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            cache_dir = os.environ.get("PYGHIDRA_L2_CACHE_DIR") or os.path.join(
                os.path.expanduser("~"), ".cache"
            )
            os.makedirs(cache_dir, exist_ok=True)
            db_path = os.path.join(cache_dir, DEFAULT_L2_CACHE_FILENAME)
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @contextlib.contextmanager
    def _conn_ctx(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _init_db(self) -> None:
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS oracle_cache (
                            query_type TEXT NOT NULL,
                            query_key TEXT NOT NULL,
                            data_json TEXT NOT NULL,
                            timestamp REAL NOT NULL,
                            PRIMARY KEY (query_type, query_key)
                        )
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_oracle_cache_timestamp
                        ON oracle_cache(timestamp)
                    """)
                    conn.commit()
            except Exception as e:
                logger.warning("Failed to initialize L2 SQLite cache at %s: %s", self.db_path, e)

    def get(self, query_type: str, query_key: str) -> dict[str, Any] | None:
        """
        Retrieves a cached query result by query_type and case-insensitive query_key.
        Returns None on cache miss.
        """
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute(
                        "SELECT data_json, timestamp FROM oracle_cache WHERE query_type = ? AND query_key = ?",
                        (query_type, str(query_key).lower()),
                    )
                    row = cur.fetchone()
                    if row:
                        data: dict[str, Any] = json.loads(row[0])
                        data["l2_cached"] = True
                        data["l2_timestamp"] = float(row[1])
                        return data
            except Exception as e:
                logger.debug("L2 cache read error: %s", e)
        return None

    def put(
        self,
        query_type: str,
        query_key: str,
        data: dict[str, Any],
        timestamp: float | None = None,
    ) -> None:
        """
        Stores or replaces an entry in the persistent L2 cache.
        Keys are case-insensitively normalized to lowercase.
        """
        with self._lock:
            try:
                data_copy = dict(data)
                data_copy.pop("l2_cached", None)
                data_copy.pop("cached", None)
                data_copy.pop("l2_timestamp", None)
                ts = timestamp if timestamp is not None else time.time()
                with self._conn_ctx() as conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO oracle_cache (query_type, query_key, data_json, timestamp)
                        VALUES (?, ?, ?, ?)
                        """,
                        (query_type, str(query_key).lower(), json.dumps(data_copy), ts),
                    )
                    conn.commit()
            except Exception as e:
                logger.debug("L2 cache write error: %s", e)

    def evict(
        self,
        query_type: str | None = None,
        query_key: str | None = None,
        older_than_sec: float | None = None,
        max_entries: int | None = None,
    ) -> int:
        """
        Evicts cached entries by query_type, query_key, TTL age, or capacity limit.
        Returns the number of removed rows.
        """
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    # Capacity-based eviction
                    if max_entries is not None and max_entries >= 0:
                        cur = conn.execute("SELECT COUNT(*) FROM oracle_cache")
                        count = cur.fetchone()[0]
                        if count > max_entries:
                            excess = count - max_entries
                            cur = conn.execute(
                                """
                                DELETE FROM oracle_cache
                                WHERE rowid IN (
                                    SELECT rowid FROM oracle_cache
                                    ORDER BY timestamp ASC
                                    LIMIT ?
                                )
                                """,
                                (excess,),
                            )
                            conn.commit()
                            return cur.rowcount
                        return 0

                    conditions: list[str] = []
                    params: list[Any] = []
                    if query_type is not None:
                        conditions.append("query_type = ?")
                        params.append(query_type)
                    if query_key is not None:
                        conditions.append("query_key = ?")
                        params.append(str(query_key).lower())
                    if older_than_sec is not None:
                        cutoff = time.time() - older_than_sec
                        conditions.append("timestamp < ?")
                        params.append(cutoff)

                    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
                    cur = conn.execute(f"DELETE FROM oracle_cache {where_clause}", params)
                    conn.commit()
                    return cur.rowcount
            except Exception as e:
                logger.warning("L2 cache eviction error: %s", e)
                return 0

    def clear(self) -> int:
        """Wipes all records from the L2 cache. Returns count of deleted entries."""
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute("DELETE FROM oracle_cache")
                    deleted = cur.rowcount
                    conn.commit()
                    return deleted
            except Exception as e:
                logger.warning("L2 cache clear error: %s", e)
                return 0

    def count(self) -> int:
        """Returns the total number of cached entries across all query types."""
        with self._lock:
            try:
                with self._conn_ctx() as conn:
                    cur = conn.execute("SELECT COUNT(*) FROM oracle_cache")
                    row = cur.fetchone()
                    return row[0] if row else 0
            except Exception as e:
                logger.debug("L2 cache count error: %s", e)
                return 0

    def close(self) -> None:
        """Closes any persistent resources."""
        pass


_GLOBAL_L2_CACHE: L2SQLiteCache | None = None
_GLOBAL_L2_CACHE_LOCK = threading.Lock()


def get_l2_cache(db_path: str | Path | None = None) -> L2SQLiteCache:
    """Returns the singleton L2SQLiteCache instance."""
    global _GLOBAL_L2_CACHE
    with _GLOBAL_L2_CACHE_LOCK:
        if _GLOBAL_L2_CACHE is None or (db_path is not None and str(_GLOBAL_L2_CACHE.db_path) != str(db_path)):
            _GLOBAL_L2_CACHE = L2SQLiteCache(db_path=db_path)
        return _GLOBAL_L2_CACHE
