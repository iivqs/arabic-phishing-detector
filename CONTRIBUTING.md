# Contributing

Contributions are welcome. Here's how:

## Adding More Brands

Open `detector/brands.py` and add an entry to the `SAUDI_BRANDS` dict:

```python
"Brand Name": "legit-domain.com.sa",
```

Make sure the value is the **canonical domain** (the one in the address bar of the real site, without `www.`).

## Reporting False Positives

If the tool flags a legitimate site, open an issue with:
- The URL that was flagged
- Which check triggered it
- Why you believe it's a false positive

## Code Changes

1. Fork the repo and create a branch
2. Write or update tests in `tests/`
3. Run `python -m pytest tests/` — all tests must pass
4. Open a pull request with a clear description

## Adding a New Check

Each check lives in `detector/checks/` and must:
- Be a module with a `check(url: str) -> dict` function
- Return a dict with keys: `name`, `status`, `score`, `detail`
- Handle all exceptions gracefully — never crash, return `status: "UNKNOWN"` instead
- Be imported and called in `detector/analyzer.py`
