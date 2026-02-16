# Polymarket Arb Bot

Binary market arbitrage scanner for Polymarket + Kalshi cross-platform opportunities.

## How It Works

On prediction markets, YES + NO should sum to $1.00. When they don't (e.g., YES=$0.45, NO=$0.50 → $0.95), buy both for a guaranteed $0.05 profit per dollar.

## Architecture

- **Gamma API** (`gamma-api.polymarket.com`) — market discovery with category/tag filtering
- **CLOB API** (`clob.polymarket.com`) — orderbook pricing (actual best ask, not indicative)
- **py-clob-client** — on-chain Polygon order placement (live mode only)
- **Kalshi API** — RSA PSS-signed requests for cross-platform arb detection

## Quick Start

```bash
pip install -r requirements.txt

# Simulation with sample data
python polymarket_arb.py --simulate

# Live scanning (still sim mode by default)
python polymarket_arb.py

# View trade log
python polymarket_arb.py --report
```

## Live Trading

```bash
# Set env vars
export POLY_PRIVATE_KEY="your-polygon-private-key"
export POLY_FUNDER="your-funder-address"
export KALSHI_KEY_ID="your-key-id"
export KALSHI_PRIVATE_KEY_PATH="/path/to/kalshi.pem"

# Run live (5s abort window on startup)
python polymarket_arb.py --live
```

## Configuration (`config.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `simulation` | `True` | Sim mode — no real orders |
| `scan_interval_seconds` | `15` | Seconds between scans (10-30) |
| `arb_threshold` | `0.99` | Buy if YES+NO < this |
| `trade_amount_usd` | `15.0` | Per-side trade amount |
| `max_daily_spend_usd` | `50.0` | Daily spend cap |
| `category_filter` | `["sports","weather","crypto","politics"]` | Market categories |
| `min_profit_margin` | `0.005` | Min profit per $1 |

## Output

Trades logged to `trade_log.csv`:
```
timestamp, market_id, question, yes_price, no_price, combined, spread, amount, cost, profit, pct, sim, source
```

## ⚠️ Disclaimer

This is experimental. Prediction market arb edges are rare and thin. Fees, slippage, and execution risk can eat profits. Start with simulation. Use at your own risk.
