#!/usr/bin/env python3
"""
Polymarket Binary Market Arbitrage Bot
======================================
Scans Polymarket (and optionally Kalshi) for binary market arbitrage:
  Buy YES + NO when combined price < $1.00 for guaranteed profit.

Uses:
  - Gamma API for market discovery (category/tag filtering)
  - CLOB API for orderbook pricing and order placement
  - py-clob-client SDK for on-chain Polygon trades (live mode)
  - Kalshi RSA-signed API for cross-platform arb

DEFAULT: Simulation mode. Set config.simulation = False for live trading.

Usage:
    python polymarket_arb.py              # Run scanner (simulation)
    python polymarket_arb.py --simulate   # Run with sample data demo
    python polymarket_arb.py --report     # Print P&L summary
    python polymarket_arb.py --live       # Live trading (requires keys)
"""

from __future__ import annotations

import asyncio
import base64
import csv
import json
import logging
import os
import random
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from enum import Enum
from pathlib import Path
from typing import Any

import aiohttp

from config import Config

# Optional: py-clob-client for real Polymarket trading
try:
    from py_clob_client.client import ClobClient
    from py_clob_client.constants import Polygon
    HAS_CLOB_CLIENT = True
except ImportError:
    HAS_CLOB_CLIENT = False

# Optional: Kalshi RSA signing
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ─── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-7s │ %(name)s │ %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("arb")


# ─── Data Models ───────────────────────────────────────────────────────────────

class Side(str, Enum):
    YES = "YES"
    NO = "NO"


@dataclass
class MarketSnapshot:
    """A binary market at a point in time."""
    market_id: str
    condition_id: str
    question: str
    yes_price: float
    no_price: float
    yes_token_id: str
    no_token_id: str
    volume: float = 0.0
    liquidity: float = 0.0
    category: str = ""
    end_date: str = ""
    source: str = "polymarket"

    @property
    def combined_price(self) -> float:
        return self.yes_price + self.no_price

    @property
    def arb_profit_per_dollar(self) -> float:
        if self.combined_price <= 0:
            return 0.0
        return max(0.0, (1.0 - self.combined_price) / self.combined_price)

    @property
    def spread(self) -> float:
        return 1.0 - self.combined_price


@dataclass
class ArbOpportunity:
    market: MarketSnapshot
    expected_profit_usd: float
    trade_amount_per_side: float
    yes_shares: float
    no_shares: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class DailyPnL:
    date: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    total_spent: float = 0.0
    total_payout: float = 0.0
    trades: int = 0
    arbs_detected: int = 0
    arbs_executed: int = 0

    @property
    def net_pnl(self) -> float:
        return self.total_payout - self.total_spent

    def can_trade(self, amount: float, max_daily: float) -> bool:
        return (self.total_spent + amount) <= max_daily


# ─── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter safe for concurrent async use."""
    def __init__(self, rps: float):
        self._rps = rps
        self._sem = asyncio.Semaphore(int(rps))  # Max concurrent slots
        self._interval = 1.0 / rps

    async def acquire(self):
        await self._sem.acquire()
        # Release the slot after the interval to maintain the rate
        asyncio.get_event_loop().call_later(self._interval, self._sem.release)


# ─── Trade Logger ──────────────────────────────────────────────────────────────

class TradeLogger:
    HEADERS = [
        "timestamp", "market_id", "question", "yes_price", "no_price",
        "combined_price", "spread", "amount_per_side", "total_cost",
        "expected_profit", "profit_pct", "simulated", "source",
    ]

    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            with self.path.open("w", newline="") as f:
                csv.writer(f).writerow(self.HEADERS)

    def log_arb(self, opp: ArbOpportunity, simulated: bool):
        m = opp.market
        total_cost = opp.trade_amount_per_side * 2
        row = [
            opp.timestamp, m.market_id, m.question[:80],
            f"{m.yes_price:.4f}", f"{m.no_price:.4f}",
            f"{m.combined_price:.4f}", f"{m.spread:.4f}",
            f"{opp.trade_amount_per_side:.2f}", f"{total_cost:.2f}",
            f"{opp.expected_profit_usd:.4f}",
            f"{opp.expected_profit_usd / total_cost * 100:.2f}%",
            simulated, m.source,
        ]
        with self.path.open("a", newline="") as f:
            csv.writer(f).writerow(row)


# ─── Kalshi Auth ───────────────────────────────────────────────────────────────

class KalshiAuth:
    """RSA PSS signing for Kalshi API requests."""

    def __init__(self, key_id: str, private_key_path: str):
        self.key_id = key_id
        self._private_key = None
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

    @property
    def is_configured(self) -> bool:
        return bool(self.key_id and self._private_key)

    def sign_request(self, method: str, path: str) -> dict[str, str]:
        """Generate signed headers for a Kalshi API request."""
        timestamp_ms = int(time.time() * 1000)
        timestamp_str = str(timestamp_ms)
        path_clean = path.split("?")[0]
        message = f"{timestamp_str}{method.upper()}{path_clean}"

        signature = self._private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return {
            "KALSHI-ACCESS-KEY": self.key_id,
            "KALSHI-ACCESS-TIMESTAMP": timestamp_str,
            "KALSHI-ACCESS-SIGNATURE": base64.b64encode(signature).decode("utf-8"),
        }


# ─── Polymarket Client ─────────────────────────────────────────────────────────

class PolymarketClient:
    """Async client using Gamma API for discovery + CLOB API for orderbook/trading."""

    def __init__(self, config: Config, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.gamma_url = config.polymarket_gamma_url
        self.clob_url = config.polymarket_clob_url
        self.limiter = RateLimiter(config.polymarket_rps)
        self._clob_client = None
        # In-memory market map for WebSocket updates (token_id -> MarketSnapshot)
        self.markets: list[MarketSnapshot] = []
        self._token_map: dict[str, tuple[MarketSnapshot, str]] = {}  # token_id -> (market, "yes"|"no")
        self.ws_last_update: float = 0.0  # Monotonic timestamp of last WS price update

        # Setup py-clob-client for live trading
        if not config.simulation and HAS_CLOB_CLIENT and config.poly_private_key:
            try:
                client = ClobClient(
                    host=config.polymarket_clob_url,
                    key=config.poly_private_key,
                    chain_id=Polygon.CHAIN_ID,
                )
                creds = client.derive_api_key()
                self._clob_client = ClobClient(
                    host=config.polymarket_clob_url,
                    key=config.poly_private_key,
                    chain_id=Polygon.CHAIN_ID,
                    creds=creds,
                    signature_type=1,  # POLY_PROXY
                    funder=config.poly_funder,
                )
                log.info("✅ py-clob-client initialized for live trading")
            except Exception as e:
                log.error(f"Failed to init py-clob-client: {e}")

    async def _get(self, base: str, path: str, params: dict | None = None) -> Any:
        await self.limiter.acquire()
        url = f"{base}{path}"
        try:
            async with self.session.get(
                url, params=params,
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                if r.status == 429:
                    log.warning("Rate limited, backing off 5s")
                    await asyncio.sleep(5)
                    return None
                if r.status != 200:
                    log.debug(f"{path} returned {r.status}")
                    return None
                return await r.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.warning(f"Request failed: {e}")
            return None

    async def get_all_active_markets(self) -> list[MarketSnapshot]:
        """Fetch ALL active binary markets from Gamma API (no category filter)."""
        all_markets: list[MarketSnapshot] = []
        offset = 0
        limit = 100

        while len(all_markets) < self.config.max_markets_per_scan:
            data = await self._get(
                self.gamma_url, "/markets",
                {"active": "true", "closed": "false", "limit": str(limit), "offset": str(offset)},
            )
            if not data:
                break

            items = data if isinstance(data, list) else data.get("data", [])
            if not items:
                break

            for m in items:
                try:
                    clob_ids = m.get("clobTokenIds")
                    if isinstance(clob_ids, str):
                        clob_ids = json.loads(clob_ids)

                    # Only binary markets with exactly 2 clobTokenIds
                    if not clob_ids or len(clob_ids) != 2:
                        continue

                    end_date_str = m.get("endDate", m.get("end_date_iso", ""))

                    # Filter by resolution date if configured
                    if self.config.max_resolution_days > 0 and end_date_str:
                        try:
                            end_dt = datetime.fromisoformat(end_date_str.replace("Z", "+00:00"))
                            cutoff = datetime.now(timezone.utc) + timedelta(days=self.config.max_resolution_days)
                            if end_dt > cutoff:
                                continue  # Skip long-dated markets
                        except (ValueError, TypeError):
                            pass  # Keep markets with unparseable dates

                    all_markets.append(MarketSnapshot(
                        market_id=str(m.get("id", "")),
                        condition_id=str(m.get("conditionId", m.get("condition_id", ""))),
                        question=m.get("question", m.get("title", "?")),
                        yes_price=0.0,  # Filled from CLOB /price
                        no_price=0.0,
                        yes_token_id=str(clob_ids[0]),
                        no_token_id=str(clob_ids[1]),
                        volume=float(m.get("volume", 0)),
                        liquidity=float(m.get("liquidity", 0)),
                        category=str(m.get("category", "")),
                        end_date=end_date_str,
                    ))
                except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                    continue

            offset += limit
            if len(items) < limit:
                break

        return all_markets[:self.config.max_markets_per_scan]

    async def get_clob_price(self, token_id: str) -> float | None:
        """Get executable price from CLOB /price endpoint (lowest ask for BUY)."""
        data = await self._get(self.clob_url, "/price", {"token_id": token_id, "side": "BUY"})
        if data and "price" in data:
            price = float(data["price"])
            return price if price > 0 else None
        return None

    async def get_ask_liquidity(self, token_id: str) -> float:
        """Get USD size available at best ask from CLOB orderbook."""
        data = await self._get(self.clob_url, "/book", {"token_id": token_id})
        if not data:
            return 0.0
        asks = data.get("asks", [])
        if not asks:
            return 0.0
        total = 0.0
        for a in asks:
            total += float(a.get("price", 0)) * float(a.get("size", 0))
        return total

    async def price_markets(self, markets: list[MarketSnapshot]) -> list[MarketSnapshot]:
        """Fill executable prices from CLOB /price in parallel, filter by liquidity."""
        priced: list[MarketSnapshot] = []
        lock = asyncio.Lock()

        async def fetch_one(m: MarketSnapshot):
            yes_ask = await self.get_clob_price(m.yes_token_id)
            no_ask = await self.get_clob_price(m.no_token_id)
            if not yes_ask or not no_ask:
                return
            m.yes_price = yes_ask
            m.no_price = no_ask

            # Liquidity filter only for potential arbs (saves API calls)
            if m.combined_price < self.config.arb_threshold:
                yes_liq = await self.get_ask_liquidity(m.yes_token_id)
                no_liq = await self.get_ask_liquidity(m.no_token_id)
                if yes_liq < self.config.min_ask_size_usd or no_liq < self.config.min_ask_size_usd:
                    log.debug(f"Low liquidity: {m.question[:40]} (Y=${yes_liq:.0f} N=${no_liq:.0f})")
                    return

            async with lock:
                priced.append(m)

        await asyncio.gather(*(fetch_one(m) for m in markets))
        return priced

    async def get_all_markets(self) -> list[MarketSnapshot]:
        """Discover ALL active binary markets via Gamma, price via CLOB /price."""
        markets = await self.get_all_active_markets()
        # Sort by volume descending — high-volume markets get priced first
        markets.sort(key=lambda m: m.volume, reverse=True)
        res_label = f", resolving ≤{self.config.max_resolution_days}d" if self.config.max_resolution_days > 0 else ""
        log.info(f"   Gamma API returned {len(markets)} active binary markets (sorted by volume{res_label})")
        priced = await self.price_markets(markets)
        log.info(f"   {len(priced)} markets priced from CLOB (liq >= ${self.config.min_ask_size_usd})")
        # Build token map for WebSocket
        self.markets = priced
        self._token_map = {}
        for m in priced:
            self._token_map[m.yes_token_id] = (m, "yes")
            self._token_map[m.no_token_id] = (m, "no")
        return priced

    # ── WebSocket Streaming ────────────────────────────────────────────────────

    WS_URL = "wss://ws-subscriptions-clob.polymarket.com/ws/market"

    async def ws_stream(self, engine: Any) -> None:
        """
        Connect to CLOB WebSocket and stream real-time price updates.
        Detects arbs via engine and fires execution immediately.
        Reconnects automatically on disconnect.
        """
        if not self._token_map:
            log.warning("No markets loaded — call get_all_markets first")
            return

        token_ids = list(self._token_map.keys())
        chunk_size = 100
        reconnect_delay = 1.0

        while True:
            try:
                async with self.session.ws_connect(
                    self.WS_URL,
                    timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
                    heartbeat=30,
                ) as ws:
                    for i in range(0, len(token_ids), chunk_size):
                        chunk = token_ids[i:i + chunk_size]
                        await ws.send_json({"auth": {}, "type": "market", "assets_ids": chunk})
                    log.info(f"🔌 WebSocket connected — streaming {len(token_ids)} tokens")
                    reconnect_delay = 1.0

                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                data = json.loads(msg.data)
                            except (json.JSONDecodeError, ValueError):
                                continue
                            self._process_ws_message(data, engine)
                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            log.warning(f"WebSocket closed: {msg.data}")
                            break

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                log.warning(f"WebSocket error: {e} — reconnecting in {reconnect_delay:.0f}s")
            except asyncio.CancelledError:
                log.info("WebSocket stream cancelled")
                return

            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 30.0)

    def _process_ws_message(self, data: Any, engine: Any) -> None:
        """Parse a WS message and update in-memory prices."""
        if isinstance(data, list):
            for entry in data:
                asset_id = entry.get("asset_id", "")
                asks = entry.get("asks", [])
                if asset_id in self._token_map and asks:
                    best_ask = float(min(asks, key=lambda a: float(a["price"]))["price"])
                    self._apply_price(asset_id, best_ask, engine)
        elif isinstance(data, dict) and "price_changes" in data:
            for pc in data["price_changes"]:
                asset_id = pc.get("asset_id", "")
                best_ask_str = pc.get("best_ask")
                if asset_id in self._token_map and best_ask_str:
                    self._apply_price(asset_id, float(best_ask_str), engine)

    def _apply_price(self, token_id: str, new_ask: float, engine: Any) -> None:
        """Apply a price update and fire arb execution if threshold crossed."""
        entry = self._token_map.get(token_id)
        if not entry:
            return
        market, side = entry
        self.ws_last_update = time.monotonic()
        old_combined = market.combined_price
        if side == "yes":
            market.yes_price = new_ask
        else:
            market.no_price = new_ask

        # Fire trade when threshold is newly crossed
        if market.combined_price < self.config.arb_threshold and old_combined >= self.config.arb_threshold:
            log.info(f"⚡ WS ARB DETECTED: {market.question[:60]} Σ=${market.combined_price:.4f}")
            opp = engine.detect_arb(market)
            if opp:
                asyncio.create_task(engine.execute_arb(opp, self))

    async def get_price_history(self, token_id: str, days_back: int = 30) -> list[dict]:
        """Fetch historical prices for backtesting."""
        end_ts = int(time.time())
        start_ts = end_ts - (days_back * 86400)
        data = await self._get(
            self.clob_url, "/prices-history",
            {"market": token_id, "startTs": str(start_ts), "endTs": str(end_ts)},
        )
        if data and "history" in data:
            return data["history"]
        return []

    async def place_order(self, token_id: str, side: str, price: float, size: float) -> dict | None:
        """Place a buy order. Uses py-clob-client in live mode."""
        if self.config.simulation:
            cost = size * price
            log.info(f"[SIM] BUY {size:.2f} shares of {token_id[:12]}... @ ${price:.4f} (would cost ${cost:.2f})")
            await asyncio.sleep(0.5)  # Mimic network delay
            return {"status": "simulated", "id": f"sim-{int(time.time())}", "filled": size, "avg_price": price}

        if self._clob_client:
            try:
                order = self._clob_client.create_and_post_order({
                    "token_id": token_id,
                    "price": price,
                    "size": size,
                    "side": "buy",
                }, {"tick_size": "0.0001", "neg_risk": False})
                return order
            except Exception as e:
                log.error(f"Order failed: {e}")
                return None

        log.error("No trading client available (install py-clob-client + set POLY_PRIVATE_KEY)")
        return None


# ─── Kalshi Client ─────────────────────────────────────────────────────────────

class KalshiClient:
    """Async client for Kalshi with RSA PSS-signed requests."""

    def __init__(self, config: Config, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.base = config.kalshi_base_url
        self.limiter = RateLimiter(config.kalshi_rps)
        self.auth: KalshiAuth | None = None

        if HAS_CRYPTO and config.kalshi_key_id and config.kalshi_private_key_path:
            self.auth = KalshiAuth(config.kalshi_key_id, config.kalshi_private_key_path)
            if self.auth.is_configured:
                log.info("✅ Kalshi RSA auth configured")
            else:
                log.warning("Kalshi key configured but private key not found")
                self.auth = None

    @property
    def is_authenticated(self) -> bool:
        return self.auth is not None and self.auth.is_configured

    async def _get(self, path: str, params: dict | None = None) -> Any:
        await self.limiter.acquire()
        url = f"{self.base}{path}"
        headers = {"Accept": "application/json"}
        if self.auth:
            headers.update(self.auth.sign_request("GET", path))
        try:
            async with self.session.get(
                url, params=params, headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                if r.status in (401, 403):
                    log.warning(f"Kalshi auth failed on {path}: HTTP {r.status}")
                    return None
                if r.status != 200:
                    log.debug(f"Kalshi {path} returned HTTP {r.status}")
                    return None
                return await r.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.warning(f"Kalshi request failed: {e}")
            return None

    async def get_events(self, cursor: str = "") -> tuple[list[dict], str]:
        params: dict[str, Any] = {"limit": 100, "status": "open"}
        if cursor:
            params["cursor"] = cursor
        data = await self._get("/events", params)
        if not data:
            return [], ""
        return data.get("events", []), data.get("cursor", "")

    async def test_connection(self) -> bool:
        """Test Kalshi API connectivity and auth. Returns True if working."""
        if not self.is_authenticated:
            log.warning("❌ Kalshi auth not configured (set KALSHI_KEY_ID + KALSHI_PRIVATE_KEY_PATH)")
            notify("❌ Kalshi: auth env vars not set")
            return False
        data = await self._get("/markets", {"limit": "1", "status": "open"})
        if data is None:
            log.warning("❌ Kalshi API unreachable or auth rejected")
            notify("❌ Kalshi: API request failed (check key/secret)")
            return False
        log.info("✅ Kalshi API connection OK")
        return True

    async def get_markets_direct(self, categories: list[str] | None = None, limit: int = 50) -> list[MarketSnapshot]:
        """Fetch open markets via /events with nested markets (skips parlays)."""
        markets: list[MarketSnapshot] = []
        data = await self._get("/events", {"limit": limit, "status": "open", "with_nested_markets": "true"})
        if not data:
            return markets

        for e in data.get("events", []):
            cat = e.get("category", "")
            if categories and not any(c in cat.lower() for c in categories):
                continue
            event_title = e.get("title", "")
            for m in e.get("markets", []):
                try:
                    yes_ask = int(m.get("yes_ask", 0))
                    no_ask = int(m.get("no_ask", 0))
                    if yes_ask <= 0 or no_ask <= 0 or yes_ask >= 100 or no_ask >= 100:
                        continue
                    subtitle = m.get("subtitle", "")
                    title = subtitle if subtitle and subtitle != event_title else event_title
                    markets.append(MarketSnapshot(
                        market_id=m.get("ticker", ""),
                        condition_id=m.get("ticker", ""),
                        question=title,
                        yes_price=yes_ask / 100.0,
                        no_price=no_ask / 100.0,
                        yes_token_id="",
                        no_token_id="",
                        volume=float(m.get("volume", 0)),
                        category=cat,
                        source="kalshi",
                    ))
                except (ValueError, TypeError):
                    continue
        return markets

    async def get_series_markets(self) -> list[MarketSnapshot]:
        """Fetch markets from series matching target categories."""
        markets: list[MarketSnapshot] = []
        data = await self._get("/series")
        if not data:
            return markets

        cats = [c.lower() for c in self.config.category_filter] if self.config.category_filter else []
        for s in data.get("series", []):
            if cats and not any(c in s.get("category", "").lower() for c in cats):
                continue
            ticker = s.get("ticker", "")
            m_data = await self._get("/markets", {"series_ticker": ticker, "status": "open"})
            if not m_data:
                continue
            for m in m_data.get("markets", []):
                try:
                    markets.append(MarketSnapshot(
                        market_id=m.get("ticker", ""),
                        condition_id=m.get("ticker", ""),
                        question=m.get("title", ""),
                        yes_price=float(m.get("yes_ask", 0)) / 100.0,
                        no_price=float(m.get("no_ask", 0)) / 100.0,
                        yes_token_id="",
                        no_token_id="",
                        volume=float(m.get("volume", 0)),
                        category=s.get("category", ""),
                        source="kalshi",
                    ))
                except (ValueError, TypeError):
                    continue
        return markets

    async def get_orderbook(self, ticker: str) -> tuple[float | None, float | None]:
        """Get best yes/no ask prices from Kalshi orderbook."""
        data = await self._get(f"/markets/{ticker}/orderbook")
        if not data:
            return None, None
        book = data.get("orderbook", {})
        yes_asks = book.get("yes", [])
        no_asks = book.get("no", [])
        yes_ask = min(a[0] / 100 for a in yes_asks) if yes_asks else None
        no_ask = min(a[0] / 100 for a in no_asks) if no_asks else None
        return yes_ask, no_ask

    async def place_order(self, ticker: str, side: str, count: int, price: float) -> bool:
        if self.config.simulation:
            log.info(f"[SIM] Kalshi BUY {count} {side} on {ticker} @ ${price:.2f}")
            return True
        # Live order would use signed POST
        log.warning("Kalshi live ordering not yet implemented")
        return False


# ─── Cross-Platform Matcher ───────────────────────────────────────────────────

class CrossPlatformMatcher:
    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold

    @staticmethod
    def similarity(a: str, b: str) -> float:
        return SequenceMatcher(None, a.lower(), b.lower()).ratio()

    def find_matches(
        self, poly: list[MarketSnapshot], kalshi: list[MarketSnapshot],
    ) -> list[tuple[MarketSnapshot, MarketSnapshot, float]]:
        matches = []
        for pm in poly:
            for km in kalshi:
                sim = self.similarity(pm.question, km.question)
                if sim >= self.threshold:
                    matches.append((pm, km, sim))
        matches.sort(key=lambda x: x[2], reverse=True)
        return matches

    @staticmethod
    def cross_arb_profit(poly: MarketSnapshot, kalshi: MarketSnapshot) -> tuple[float | None, str]:
        """
        Cross-platform arb: buy cheapest YES+NO combination across platforms.
        Returns (profit_per_share, strategy_description).
        """
        combo1 = poly.yes_price + kalshi.no_price  # Buy poly YES + kalshi NO
        combo2 = kalshi.yes_price + poly.no_price   # Buy kalshi YES + poly NO
        if combo1 < combo2 and combo1 < 1.0:
            return 1.0 - combo1, "buy_poly_yes_kalshi_no"
        elif combo2 < 1.0:
            return 1.0 - combo2, "buy_kalshi_yes_poly_no"
        return None, ""


# ─── Arbitrage Engine ──────────────────────────────────────────────────────────

class ArbitrageEngine:
    def __init__(self, config: Config):
        self.config = config
        self.pnl = DailyPnL()
        self.logger = TradeLogger(config.trade_log_csv)
        self.opportunities_found = 0
        self.trades_executed = 0

    def detect_arb(self, market: MarketSnapshot) -> ArbOpportunity | None:
        if market.combined_price >= self.config.arb_threshold:
            # Near-miss alert for manual review
            if market.combined_price < 0.98:
                notify(f"⚠️ Near arb: {market.question[:50]} Σ={market.combined_price:.4f}")
            return None
        if market.arb_profit_per_dollar < self.config.min_profit_margin:
            return None

        amount = min(self.config.trade_amount_usd, self.config.max_trade_usd)
        yes_shares = amount / market.yes_price if market.yes_price > 0 else 0
        no_shares = amount / market.no_price if market.no_price > 0 else 0
        min_shares = min(yes_shares, no_shares)
        total_cost = amount * 2
        expected_profit = min_shares * 1.0 - total_cost

        if expected_profit <= 0:
            return None

        self.opportunities_found += 1
        return ArbOpportunity(
            market=market,
            expected_profit_usd=expected_profit,
            trade_amount_per_side=amount,
            yes_shares=yes_shares,
            no_shares=no_shares,
        )

    async def execute_arb(self, opp: ArbOpportunity, client: PolymarketClient) -> bool:
        m = opp.market
        total_cost = opp.trade_amount_per_side * 2

        if not self.pnl.can_trade(total_cost, self.config.max_daily_spend_usd):
            log.warning(f"Daily limit: ${self.pnl.total_spent:.2f}+${total_cost:.2f} > ${self.config.max_daily_spend_usd}, skip")
            return False

        log.info("=" * 60)
        log.info(f"🎯 ARB: {m.question[:60]}")
        log.info(f"   YES=${m.yes_price:.4f}  NO=${m.no_price:.4f}  Σ=${m.combined_price:.4f}")
        log.info(f"   Spread=${m.spread:.4f}  Profit=${opp.expected_profit_usd:.4f}")
        log.info(f"   {'🔵 SIM' if self.config.simulation else '🔴 LIVE'}")
        log.info("=" * 60)

        yes_result = await client.place_order(m.yes_token_id, "BUY", m.yes_price, opp.yes_shares)
        no_result = await client.place_order(m.no_token_id, "BUY", m.no_price, opp.no_shares)

        if yes_result and no_result:
            # Model slippage/fees in sim mode
            slippage = 0.0
            if self.config.simulation:
                slippage = random.uniform(0.01, 0.02)  # 1-2%
                opp.expected_profit_usd *= (1 - slippage)
                log.info(f"[SIM] Applied {slippage*100:.1f}% slippage/fees | Adj. profit: ${opp.expected_profit_usd:.2f}")

            self.pnl.total_spent += total_cost
            self.pnl.total_payout += min(opp.yes_shares, opp.no_shares) * (1 - (slippage if self.config.simulation else 0))
            self.pnl.trades += 2
            self.pnl.arbs_executed += 1
            self.trades_executed += 1
            self.logger.log_arb(opp, self.config.simulation)
            notify(f"✅ Trade: {m.question[:40]} | Profit=${opp.expected_profit_usd:.4f} | Daily=${self.pnl.total_spent:.2f}")
            if self.config.simulation:
                log.info(f"[SIM P&L] Total spent: ${self.pnl.total_spent:.2f} | Expected payout: ${self.pnl.total_payout:.2f} | Net: ${self.pnl.net_pnl:.2f}")
            return True
        else:
            notify(f"❌ Trade failed: {m.question[:40]}")
            return False

    def print_summary(self):
        print(f"\n{'=' * 60}")
        print("📊 ARBITRAGE BOT SUMMARY")
        print("=" * 60)
        print(f"  Date:            {self.pnl.date}")
        print(f"  Mode:            {'🔵 Simulation' if self.config.simulation else '🔴 Live'}")
        print(f"  Arbs detected:   {self.opportunities_found}")
        print(f"  Arbs executed:   {self.trades_executed}")
        print(f"  Total spent:     ${self.pnl.total_spent:.2f}")
        print(f"  Expected payout: ${self.pnl.total_payout:.2f}")
        print(f"  Expected P&L:    ${self.pnl.net_pnl:.2f}")
        if self.pnl.total_spent > 0:
            print(f"  ROI:             {self.pnl.net_pnl / self.pnl.total_spent * 100:.2f}%")
        print(f"  Daily remaining: ${self.config.max_daily_spend_usd - self.pnl.total_spent:.2f}")
        if self.trades_executed > 0 and self.config.simulation:
            avg_profit = self.pnl.net_pnl / self.trades_executed
            resolve_days = self.config.max_resolution_days or 30
            monthly_arbs = self.trades_executed * (30 / resolve_days) * 4
            monthly_net = self.pnl.net_pnl * (30 / resolve_days) * 4
            roi = self.pnl.net_pnl / self.pnl.total_spent if self.pnl.total_spent > 0 else 0
            reinvest = self.config.reinvest_pct
            bankroll = self.config.max_daily_spend_usd
            print(f"  ── ≤{resolve_days}d Market Projection (after slippage) ──")
            print(f"  Avg profit/arb:  ${avg_profit:.2f}  │  ROI/arb: {roi / self.trades_executed * 100:.1f}%")
            print(f"  Est. arbs/month: ~{monthly_arbs:.0f}")
            print(f"  Est. net/month:  ~${monthly_net:.0f} (no reinvest)")
            if reinvest > 0:
                print(f"  ── Bankroll Growth ({reinvest:.0%} of profits reinvested) ──")
                print(f"  Starting:        ${bankroll:.0f}")
                for month in (1, 3, 6, 12):
                    b = bankroll
                    cycles = int(monthly_arbs) * month
                    for _ in range(cycles):
                        profit = b * roi / (monthly_arbs or 1)
                        b += profit * reinvest
                    print(f"  {month:>2}mo bankroll:   ${b:>7.0f}  (+${b - bankroll:>6.0f} net)")
        print("=" * 60 + "\n")


# ─── Notification ──────────────────────────────────────────────────────────────

def notify(message: str):
    """Notification via print + optional Telegram webhook."""
    print(f"📢 {message}")
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    tg_chat = os.getenv("TELEGRAM_CHAT_ID", "")
    if tg_token and tg_chat:
        try:
            import urllib.request
            url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            data = json.dumps({"chat_id": tg_chat, "text": message}).encode()
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # Don't let notification failures break trading


# ─── Sample Data ───────────────────────────────────────────────────────────────

def generate_sample_markets() -> list[MarketSnapshot]:
    return [
        MarketSnapshot("pm-001", "cond-001", "Will it rain in NYC on Feb 20, 2026?",
                        0.42, 0.53, "tok-y-001", "tok-n-001", 15000, 8000, "weather"),
        MarketSnapshot("pm-002", "cond-002", "Chiefs win Super Bowl LXI?",
                        0.35, 0.62, "tok-y-002", "tok-n-002", 250000, 45000, "sports"),
        MarketSnapshot("pm-003", "cond-003", "Bitcoin above $100k on March 1?",
                        0.55, 0.48, "tok-y-003", "tok-n-003", 500000, 120000, "crypto"),
        MarketSnapshot("pm-004", "cond-004", "Snow in Chicago this weekend?",
                        0.60, 0.35, "tok-y-004", "tok-n-004", 8000, 3000, "weather"),
        MarketSnapshot("pm-005", "cond-005", "Lakers make NBA playoffs 2026?",
                        0.48, 0.48, "tok-y-005", "tok-n-005", 180000, 35000, "sports"),
        MarketSnapshot("pm-006", "cond-006", "Will it snow in Miami?",
                        0.05, 0.95, "tok-y-006", "tok-n-006", 2000, 500, "weather"),
        MarketSnapshot("pm-007", "cond-007", "Fed raises rates in March?",
                        0.50, 0.50, "tok-y-007", "tok-n-007", 100000, 30000, "politics"),
        MarketSnapshot("pm-008", "cond-008", "Temperature above 80°F in Phoenix Feb 20?",
                        0.30, 0.65, "tok-y-008", "tok-n-008", 5000, 2000, "weather"),
    ]


def generate_sample_kalshi() -> list[MarketSnapshot]:
    return [
        MarketSnapshot("k-001", "", "Rain in New York City on February 20, 2026",
                        0.45, 0.58, "", "", 0, 0, "weather", source="kalshi"),
        MarketSnapshot("k-002", "", "Kansas City Chiefs to win Super Bowl LXI",
                        0.38, 0.66, "", "", 0, 0, "sports", source="kalshi"),
        MarketSnapshot("k-003", "", "Bitcoin price above $100,000 on March 1",
                        0.52, 0.51, "", "", 0, 0, "crypto", source="kalshi"),
    ]


# ─── Main Bot ─────────────────────────────────────────────────────────────────

class ArbBot:
    def __init__(self, config: Config):
        self.config = config
        self.engine = ArbitrageEngine(config)
        self.matcher = CrossPlatformMatcher(config.title_similarity_threshold)
        self._running = False

    async def run_scan_cycle(self, poly: PolymarketClient, kalshi: KalshiClient | None):
        log.info("📡 Scanning Polymarket...")
        markets = await poly.get_all_markets()
        if not markets:
            log.info("No markets returned")
            return

        for m in markets:
            opp = self.engine.detect_arb(m)
            if opp:
                await self.engine.execute_arb(opp, poly)

        # Log closest to arb for debugging
        sorted_markets = sorted(markets, key=lambda m: m.combined_price)
        log.info("── Top 5 closest markets ──")
        for m in sorted_markets[:5]:
            log.info(f"  Σ=${m.combined_price:.4f} │ Y=${m.yes_price:.4f} N=${m.no_price:.4f} │ {m.question[:55]}")

        # Cross-platform
        if kalshi:
            await self._cross_scan(markets, kalshi)
        elif self.config.simulation:
            # Run cross-arb demo with sample data even without Kalshi auth
            await self._cross_scan_sim(markets)

    async def _cross_scan(self, poly_markets: list[MarketSnapshot], kalshi: KalshiClient):
        log.info("📡 Cross-checking Kalshi...")
        kalshi_markets = await kalshi.get_markets_direct()
        if not kalshi_markets and self.config.simulation:
            log.info("[SIM] No Kalshi markets — using sample data for cross-arb demo")
            kalshi_markets = generate_sample_kalshi()
        if not kalshi_markets:
            return

        matches = self.matcher.find_matches(poly_markets, kalshi_markets)
        for pm, km, sim in matches[:5]:
            # Refresh Kalshi prices from orderbook
            k_yes, k_no = await kalshi.get_orderbook(km.market_id)
            if k_yes:
                km.yes_price = k_yes
            if k_no:
                km.no_price = k_no

            profit, strategy = self.matcher.cross_arb_profit(pm, km)
            if profit and profit > 0.01:
                log.info(f"🌐 CROSS-ARB: {pm.question[:50]}")
                log.info(f"   Poly  YES=${pm.yes_price:.2f} NO=${pm.no_price:.2f}")
                log.info(f"   Kalshi YES=${km.yes_price:.2f} NO=${km.no_price:.2f}")
                log.info(f"   Profit=${profit:.4f}/share  Strategy={strategy}  Match={sim:.0%}")

    async def _cross_scan_sim(self, poly_markets: list[MarketSnapshot]):
        """Cross-arb demo using sample Kalshi data when auth unavailable."""
        log.info("[SIM] Cross-checking with sample Kalshi data...")
        kalshi_markets = generate_sample_kalshi()
        matches = self.matcher.find_matches(poly_markets, kalshi_markets)
        for pm, km, sim in matches[:5]:
            profit, strategy = self.matcher.cross_arb_profit(pm, km)
            if profit and profit > 0.01:
                log.info(f"🌐 SIM CROSS-ARB: {pm.question[:50]}")
                log.info(f"   Poly  YES=${pm.yes_price:.2f} NO=${pm.no_price:.2f}")
                log.info(f"   Kalshi YES=${km.yes_price:.2f} NO=${km.no_price:.2f}")
                log.info(f"   Profit=${profit:.4f}/share  Strategy={strategy}  Match={sim:.0%}")

    async def run_simulation_demo(self):
        print("\n" + "🔵 " * 20)
        print("  SIMULATION MODE — Sample market data")
        print("🔵 " * 20 + "\n")

        markets = generate_sample_markets()
        kalshi_markets = generate_sample_kalshi()

        # Force a WS-style arb to demo the full execution path
        markets[0].yes_price = 0.47
        markets[0].no_price = 0.51  # Σ = 0.98 → triggers arb
        log.info("⚡ Injected forced arb: %s (Y=0.47 N=0.51 Σ=0.98)", markets[0].question[:40])

        log.info(f"Loaded {len(markets)} sample Polymarket markets")

        for m in markets:
            status = "✅ ARB" if m.combined_price < self.config.arb_threshold else "❌ PASS"
            log.info(f"  {status} │ {m.question[:50]:50s} │ Y=${m.yes_price:.2f} N=${m.no_price:.2f} │ Σ=${m.combined_price:.4f}")

        print()
        async with aiohttp.ClientSession() as session:
            dummy = PolymarketClient(self.config, session)
            for m in markets:
                opp = self.engine.detect_arb(m)
                if opp:
                    await self.engine.execute_arb(opp, dummy)

        print()
        log.info("── Cross-Platform Matching ──")
        matches = self.matcher.find_matches(markets, kalshi_markets)
        for pm, km, sim in matches:
            profit, strategy = self.matcher.cross_arb_profit(pm, km)
            profit_str = f"${profit:.4f} ({strategy})" if profit else "none"
            log.info(f"  Match ({sim:.0%}): {pm.question[:40]} ↔ {km.question[:40]}")
            log.info(f"    Poly Σ=${pm.combined_price:.2f} │ Kalshi Σ=${km.combined_price:.2f} │ X-arb: {profit_str}")

        self.engine.print_summary()

    async def run_historical_backtest(self, poly: PolymarketClient, markets: list[MarketSnapshot], days: int = 30):
        """Backtest using actual price history from CLOB API."""
        log.info(f"── Historical Backtest ({days} days) ──")
        for m in markets[:5]:
            yes_hist = await poly.get_price_history(m.yes_token_id, days)
            no_hist = await poly.get_price_history(m.no_token_id, days)
            if not yes_hist or not no_hist:
                continue
            opps = 0
            for yh, nh in zip(yes_hist, no_hist):
                if yh.get("t") == nh.get("t") and yh.get("p", 1) + nh.get("p", 1) < self.config.arb_threshold:
                    opps += 1
            log.info(f"  {m.question[:50]}: {opps} arb windows in {days}d")

    async def run_live(self):
        warnings = self.config.validate()
        for w in warnings:
            log.warning(w)
        if any("❌" in w for w in warnings):
            log.error("Fix config errors before starting")
            return

        mode = "SIMULATION" if self.config.simulation else "⚠️  LIVE TRADING"
        print(f"\n{'=' * 60}")
        print(f"  Polymarket Arb Bot — {mode}")
        print(f"  Scan: {self.config.scan_interval_seconds}s │ Threshold: <${self.config.arb_threshold}")
        print(f"  Trade: ${self.config.trade_amount_usd}/side │ Daily cap: ${self.config.max_daily_spend_usd}")
        print(f"{'=' * 60}\n")

        if not self.config.simulation:
            log.warning("🔴 LIVE TRADING — real money! Ctrl+C within 5s to abort")
            await asyncio.sleep(5)

        self._running = True
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._shutdown)

        async with aiohttp.ClientSession() as session:
            poly = PolymarketClient(self.config, session)
            kalshi = KalshiClient(self.config, session)
            kalshi_active = kalshi.is_authenticated

            ws_task: asyncio.Task | None = None

            cycle = 0
            cycle_limit = int(os.getenv("ARB_CYCLE_LIMIT", "0")) or None
            while self._running:
                cycle += 1
                log.info(f"─── Scan #{cycle}{f'/{cycle_limit}' if cycle_limit else ''} ───")
                try:
                    await self.run_scan_cycle(poly, kalshi if kalshi_active else None)
                except Exception as e:
                    log.error(f"Scan error: {e}", exc_info=True)

                # Start WS stream after first successful scan populates token map
                if ws_task is None and poly._token_map:
                    ws_task = asyncio.create_task(poly.ws_stream(self.engine))
                    log.info("🔌 WebSocket stream started in background")
                elif ws_task and ws_task.done():
                    # Restart if it crashed
                    log.warning("🔌 WebSocket task died — restarting")
                    ws_task = asyncio.create_task(poly.ws_stream(self.engine))

                # WS health check
                if poly.ws_last_update > 0:
                    silence = time.monotonic() - poly.ws_last_update
                    if silence > 60:
                        log.warning(f"🔌 WebSocket silent for {silence:.0f}s")

                if self.engine.pnl.total_spent >= self.config.max_daily_spend_usd:
                    log.warning("Daily limit reached, stopping")
                    break

                if cycle_limit and cycle >= cycle_limit:
                    log.info(f"Cycle limit ({cycle_limit}) reached, stopping")
                    break

                # Reset at midnight
                today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                if today != self.engine.pnl.date:
                    log.info("🌅 New day — resetting daily counters")
                    self.engine.pnl = DailyPnL()

                await asyncio.sleep(self.config.scan_interval_seconds)

            # Cleanup WS task
            if ws_task and not ws_task.done():
                ws_task.cancel()
                try:
                    await ws_task
                except asyncio.CancelledError:
                    pass
                log.info("🔌 WebSocket stream stopped")

        self.engine.print_summary()

    def _shutdown(self):
        log.info("🛑 Shutting down...")
        self._running = False


# ─── Report ────────────────────────────────────────────────────────────────────

def print_trade_log_report(csv_path: str):
    path = Path(csv_path)
    if not path.exists():
        print(f"No trade log at {csv_path}")
        return
    total_cost = total_profit = 0.0
    count = 0
    with path.open() as f:
        for row in csv.DictReader(f):
            count += 1
            total_cost += float(row.get("total_cost", 0))
            total_profit += float(row.get("expected_profit", "0").replace("$", ""))
    print(f"\n📋 Trade Log ({csv_path})")
    print(f"   Trades: {count}  Cost: ${total_cost:.2f}  Profit: ${total_profit:.4f}")
    if total_cost > 0:
        print(f"   ROI: {total_profit / total_cost * 100:.2f}%")


# ─── Entry ─────────────────────────────────────────────────────────────────────

async def main():
    config = Config()

    if "--live" in sys.argv:
        config.simulation = False

    bot = ArbBot(config)

    if "--report" in sys.argv:
        print_trade_log_report(config.trade_log_csv)
    elif "--backtest" in sys.argv:
        days = 90
        async with aiohttp.ClientSession() as session:
            poly = PolymarketClient(config, session)
            markets = await poly.get_all_markets()
            await bot.run_historical_backtest(poly, markets[:10], days=days)
    elif "--scan" in sys.argv:
        # Live API scan in simulation mode (real prices, no real trades)
        await bot.run_live()
    elif "--simulate" in sys.argv or config.simulation:
        await bot.run_simulation_demo()
    else:
        await bot.run_live()


if __name__ == "__main__":
    asyncio.run(main())
