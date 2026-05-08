## 2025-05-14 - Redundant AI and Network Calls
**Learning:** Streamlit reruns the entire script on every interaction (like expanding an expander). Without explicit caching in session state, expensive AI analysis and network fetch calls are re-executed, causing significant UI lag and unnecessary API costs.
**Action:** Use session state to memoize AI analysis results and `functools.lru_cache` for network fetches within a single audit pipeline execution.
