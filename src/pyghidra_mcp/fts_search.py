"""
SQLite FTS5 search backend for pyghidra-mcp.

Drop-in replacement for ChromaDB: provides BM25-ranked full-text search
over decompiled function code and extracted strings. Indexing is instant
(< 1 second for 5K functions) compared to ChromaDB's ONNX embedding
pipeline (20+ minutes).

Usage:
    db = FTS5Database("/path/to/search.db")
    db.create_code_table()
    db.add_codes_batch([(name, entry_point, code), ...])
    results = db.search_code("system sprintf", limit=10)
"""

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


class FTS5Database:
    """SQLite FTS5 database for full-text search over code and strings."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        # check_same_thread=False: index is built in background thread,
        # queried from HTTP handler thread. WAL mode ensures safe reads.
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")

    # ------------------------------------------------------------------
    # Table creation
    # ------------------------------------------------------------------

    def create_code_table(self):
        self.conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS code_fts USING fts5(
                function_name,
                entry_point UNINDEXED,
                code,
                tokenize='porter unicode61'
            )
            """
        )
        self.conn.commit()

    def create_strings_table(self):
        self.conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS strings_fts USING fts5(
                value,
                address UNINDEXED,
                tokenize='porter unicode61'
            )
            """
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Batch insertion
    # ------------------------------------------------------------------

    def add_codes_batch(self, records: list[tuple[str, str, str]]):
        """Insert decompiled functions. records: [(name, entry_point, code)]"""
        self.conn.executemany(
            "INSERT INTO code_fts (function_name, entry_point, code) VALUES (?, ?, ?)",
            records,
        )
        self.conn.commit()

    def add_strings_batch(self, records: list[tuple[str, str]]):
        """Insert strings. records: [(value, address)]"""
        self.conn.executemany(
            "INSERT INTO strings_fts (value, address) VALUES (?, ?)",
            records,
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Code search
    # ------------------------------------------------------------------

    def search_code_literal(
        self, query: str, limit: int = 10, offset: int = 0
    ) -> list[tuple[str, str, str]]:
        """Substring search using LIKE. Returns [(name, entry_point, code)]."""
        cursor = self.conn.execute(
            "SELECT function_name, entry_point, code FROM code_fts "
            "WHERE code LIKE ? LIMIT ? OFFSET ?",
            (f"%{query}%", limit, offset),
        )
        return cursor.fetchall()

    def count_code_literal(self, query: str) -> int:
        """Count functions whose code contains the literal substring."""
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM code_fts WHERE code LIKE ?",
            (f"%{query}%",),
        )
        return cursor.fetchone()[0]

    def search_code_bm25(
        self, query: str, limit: int = 10, offset: int = 0
    ) -> list[tuple[str, str, str, float]]:
        """BM25-ranked FTS5 search. Returns [(name, entry_point, code, rank)].

        FTS5 rank is negative (lower = better match). We return the raw rank;
        callers convert to a 0-1 similarity score.
        """
        fts_query = _to_fts_query(query)
        try:
            cursor = self.conn.execute(
                "SELECT function_name, entry_point, code, rank "
                "FROM code_fts WHERE code_fts MATCH ? "
                "ORDER BY rank LIMIT ? OFFSET ?",
                (fts_query, limit, offset),
            )
            return cursor.fetchall()
        except sqlite3.OperationalError as e:
            # Bad FTS5 query syntax — fall back to literal search
            logger.debug("FTS5 match failed (%s), falling back to LIKE", e)
            rows = self.search_code_literal(query, limit, offset)
            return [(r[0], r[1], r[2], -1.0) for r in rows]

    def count_code(self) -> int:
        """Total number of indexed functions."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM code_fts")
        return cursor.fetchone()[0]

    # ------------------------------------------------------------------
    # String search
    # ------------------------------------------------------------------

    def search_strings_literal(
        self, query: str, limit: int = 100
    ) -> list[tuple[str, str]]:
        """Substring search. Returns [(value, address)]."""
        cursor = self.conn.execute(
            "SELECT value, address FROM strings_fts WHERE value LIKE ? LIMIT ?",
            (f"%{query}%", limit),
        )
        return cursor.fetchall()

    def search_strings_bm25(
        self, query: str, limit: int = 100
    ) -> list[tuple[str, str, float]]:
        """BM25-ranked string search. Returns [(value, address, rank)]."""
        fts_query = _to_fts_query(query)
        try:
            cursor = self.conn.execute(
                "SELECT value, address, rank FROM strings_fts "
                "WHERE strings_fts MATCH ? ORDER BY rank LIMIT ?",
                (fts_query, limit),
            )
            return cursor.fetchall()
        except sqlite3.OperationalError as e:
            logger.debug("FTS5 match failed (%s), falling back to LIKE", e)
            rows = self.search_strings_literal(query, limit)
            return [(r[0], r[1], -1.0) for r in rows]

    def close(self):
        self.conn.close()


def _to_fts_query(query: str) -> str:
    """Convert a natural-language query to an FTS5 query string.

    Splits on whitespace, quotes each token, joins with OR.
    Example: 'system sprintf' -> '"system" OR "sprintf"'

    Quoting prevents FTS5 syntax errors from special characters
    in decompiled code (parentheses, operators, etc.).
    """
    tokens = query.split()
    if not tokens:
        return '""'
    # Quote each token to handle special chars in decompiled code
    quoted = [f'"{t}"' for t in tokens]
    return " OR ".join(quoted)
