# Understood Errors & Anti-Patterns Log

## 1. Security & Linter Scans (Bandit & MyPy)
- **Bandit `B404`, `B603`, `B607`, `B110`**:
  - `B404` (`blacklist_imports`): Mark intentional `import subprocess` with `# nosec B404`.
  - `B607` (`start_process_with_partial_path`) & `B603` (`subprocess_without_shell_equals_true`): Dynamically resolve executable paths with `shutil.which("ifconfig")` (or fallback `/sbin/ifconfig`) and annotate with `# nosec B603 B607`.
  - `B110` (`try_except_pass`): Avoid bare `pass` in `except Exception:` blocks. Catch exceptions explicitly (e.g. `except Exception as err:`) and log them using `logger.debug(...)`.
- **MyPy Variable Re-assignment Error**:
  - *Error*: `Incompatible types in assignment (expression has type "tuple[...]", variable has type "str")`
  - *Root Cause*: Re-using the same variable name (`route`) for both Scapy route tuples and string interface names.
  - *Rule*: Use distinct variable names for different types (e.g., `route_res`, `route_name`, `route_entry`, `ifc_entry`).

## 2. Code Linting (Ruff `F821`)
- **Ruff `F821` (`Undefined name end_obj`)**:
  - *Root Cause*: Overwriting unpacked variable names during refactoring (`start_ip, end_ip` vs `end_obj`).
  - *Rule*: Keep unpacked input strings (`end_ip_str`) clearly distinguished from instantiated type objects (`end_obj`).

## 3. Asyncio Test Mocking & Executings
- **Mock Bypass in `socket.getnameinfo`**:
  - *Error*: `AssertionError: assert None == 'printer.local'`
  - *Root Cause*: `asyncio.get_running_loop().getnameinfo()` calls C-level loop methods and bypasses `unittest.mock.patch("socket.getnameinfo")`.
  - *Rule*: Execute socket lookups with `loop.run_in_executor(None, socket.getnameinfo, ...)` so Python unit test mocks correctly intercept the target function.
- **Future vs Coroutine AttributeError in Test Mocks**:
  - *Error*: `AttributeError: '_asyncio.Future' object has no attribute 'close'`
  - *Root Cause*: Mocking `asyncio.wait_for` and calling `coro.close()` when `run_in_executor` returns a `Future` object instead of a `Coroutine`.
  - *Rule*: Safely check available methods before cleanup in async mock side-effects:
    ```python
    if hasattr(coro, "close"):
        coro.close()
    elif hasattr(coro, "cancel"):
        coro.cancel()
    ```
