"""Configuration for Polymarket Arbitrage Bot."""

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # --- Mode ---
    simulation: bool = True  # DEFAULT ON. Set False for live trading.

    # --- API Endpoints ---
    polymarket_clob_url: str = "https://clob.polymarket.com"
    polymarket_gamma_url: str = "https://gamma-api.polymarket.com"
    kalshi_base_url: str = "https://api.elections.kalshi.com/trade-api/v2"

    # --- API Keys (from env) ---
    # Polymarket: uses py-clob-client with private key for on-chain trading
    poly_private_key: str = field(default_factory=lambda: os.getenv("POLY_PRIVATE_KEY", ""))
    poly_funder: str = field(default_factory=lambda: os.getenv("POLY_FUNDER", ""))
    # Kalshi: RSA key-based auth (PSS signing)
    kalshi_key_id: str = field(default_factory=lambda: os.getenv("KALSHI_KEY_ID", ""))
    kalshi_private_key_path: str = field(default_factory=lambda: os.getenv("KALSHI_PRIVATE_KEY_PATH", ""))

    # --- Scanning ---
    scan_interval_seconds: int = 10  # 10-30 configurable
    max_markets_per_scan: int = 200

    # --- Arbitrage Thresholds ---
    arb_threshold: float = 0.99  # Buy if YES + NO < this
    min_profit_margin: float = 0.01  # Minimum $0.01 profit per $1 after fees

    # --- Trade Sizing ---
    trade_amount_usd: float = 12.50  # Per-side amount ($10-15 range)
    max_trade_usd: float = 15.0
    min_trade_usd: float = 10.0

    # --- Risk Management ---
    max_daily_spend_usd: float = 50.0
    max_open_positions: int = 10
    max_slippage_pct: float = 0.02  # 2% max slippage
    reinvest_pct: float = 0.50  # Reinvest 50% of profits into new trades

    # --- Market Filters ---
    category_filter: list[str] = field(default_factory=list)  # Empty = scan ALL
    min_liquidity_usd: float = 100.0  # Skip illiquid markets
    min_volume_usd: float = 50.0
    min_ask_size_usd: float = 50.0  # Both asks must have >= this size
    max_resolution_days: int = 30  # Only markets resolving within N days (0 = no filter)

    # --- Logging ---
    trade_log_csv: str = "trade_log.csv"
    log_level: str = "INFO"

    # --- Rate Limiting ---
    polymarket_rps: float = 5.0  # Requests per second
    kalshi_rps: float = 2.0

    # --- Cross-Platform ---
    title_similarity_threshold: float = 0.6  # For fuzzy matching events

    def validate(self) -> list[str]:
        """Return list of warnings."""
        warnings = []
        if not self.simulation:
            warnings.append("⚠️  LIVE TRADING ENABLED — real money at risk!")
            if not self.poly_private_key:
                warnings.append("❌ POLY_PRIVATE_KEY not set — needed for Polymarket trades")
        if self.trade_amount_usd > self.max_trade_usd:
            warnings.append(f"trade_amount ({self.trade_amount_usd}) > max_trade ({self.max_trade_usd})")
        if self.scan_interval_seconds < 5:
            warnings.append("scan_interval < 5s risks rate limiting")
        return warnings
