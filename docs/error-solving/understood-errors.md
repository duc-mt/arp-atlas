# Understood Errors & Anti-Patterns Log

## 1. Bandit & MyPy Scans
- **Bandit B404 / B603 / B607 / B110**:
  - Always use `# nosec B404` when importing `subprocess` is intentional.
  - Dynamically resolve executable paths with `shutil.which("<binary>")` (or fallback full path) and annotate calls with `# nosec B603 B607`.
  - Never use empty `pass` in `except Exception:` blocks; catch explicit errors and log debug messages with `logger.debug(...)`.
- **MyPy Variable Re-assignment**:
  - Do not reuse the same variable name across different types in loop constructs (e.g. re-assigning a tuple or `NetworkInterface` object to a `str`).

## 2. Asyncio Executings & Mocking in Tests
- **`socket.getnameinfo` & Event Loops**:
  - `loop.getnameinfo()` in Python asyncio bypasses `unittest.mock.patch("socket.getnameinfo")`. Use `loop.run_in_executor(None, socket.getnameinfo, ...)` to ensure test mocks intercept the call cleanly.
- **Asyncio Wait For Mocks**:
  - When mocking `asyncio.wait_for`, the target awaitable could be a `Coroutine` (which implements `.close()`) or a `Future` / `Task` (which implements `.cancel()`). Always safely check `hasattr(coro, "close")` or `hasattr(coro, "cancel")` before calling.

## 3. Variable Naming & Ruff Linters
- **Typo Prevention**:
  - Distinguish raw split strings from converted objects (e.g. `end_ip_str` vs `end_obj`) to prevent `F821 Undefined name` errors from linters like Ruff.
