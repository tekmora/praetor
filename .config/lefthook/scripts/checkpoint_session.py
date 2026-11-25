# SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Session ownership shared by native hooks and checkpoint callers (Python 3.10+)."""

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

SESSION_GIT_TIMEOUT = 2
SESSION_GIT_GRACE = 0.5
SESSION_GIT_OUTPUT = 16 * 1024

# Shared native checkpoint session records: Python adapters and the Go hook caller.
SESSION_ENV = "PRAETOR_CHECKPOINT_SESSION"
SESSION_INPUT_LIMIT = 1024 * 1024
MAX_WORKTREES = 512
MAX_RECORD_BYTES = 512 * 1024
MAX_SESSION_RECORDS = 10000
# One age bound for recent worktree activity and inactive ownership records.
# Records exactly at this bound remain fresh; only older records expire.
WORKTREE_ACTIVITY_WINDOW = 24 * 60 * 60
SESSION_LOCK_STALE_SECONDS = 30
# Bound work under the kernel lock independently of the legacy token expiry.
SESSION_LOCK_MAX_HOLD_SECONDS = 5
# POSIX record locks belong to the process. Serialize opens of each locked inode
# within this interpreter too: closing a second descriptor would drop its lock.
_SESSION_GUARDS = tuple(threading.Lock() for _ in range(16))


def extract_session_id(payload):
    """Read session ID from agent payload without guessing."""
    if not isinstance(payload, dict):
        return None
    session_id = payload.get("session_id")
    if isinstance(session_id, str) and session_id.strip():
        return session_id.strip()
    conv_id = payload.get("conversationId")
    if isinstance(conv_id, str) and conv_id.strip():
        return conv_id.strip()
    return None


def session_hash_for(session_id):
    """Return first 16 hex chars of SHA256 of session ID. Never store raw ID."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


def _git_common_dir(root, budget):
    """Resolve repository common Git directory."""
    from common import clean_env, run_bounded

    raw = run_bounded(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=root,
        env=clean_env(),
        timeout=budget.timeout(SESSION_GIT_TIMEOUT),
        max_output=SESSION_GIT_OUTPUT,
        grace=SESSION_GIT_GRACE,
    )
    return Path(raw.decode().strip()).resolve()


def _listed_worktrees(root, budget):
    """Read bounded NUL-delimited worktree listing."""
    from common import clean_env, run_bounded

    raw = run_bounded(
        ["git", "worktree", "list", "--porcelain", "-z"],
        cwd=root,
        env=clean_env(),
        timeout=budget.timeout(SESSION_GIT_TIMEOUT),
        max_output=SESSION_INPUT_LIMIT,
        grace=SESSION_GIT_GRACE,
    )
    entries, entry = [], {}
    for part in raw.split(b"\0"):
        field = os.fsdecode(part)
        if not field:
            if entry and "path" in entry:
                entries.append(entry)
                entry = {}
            if len(entries) >= MAX_WORKTREES:
                break
            continue
        key, sep, val = field.partition(" ")
        if key == "worktree" and sep:
            entry["path"] = val
    if entry and "path" in entry and len(entries) < MAX_WORKTREES:
        entries.append(entry)
    return entries


MAX_EXTRACT_NODES = 256


def _extract_strings(data):
    """Extract string values iteratively from tool input under a scalar bound."""
    result = []
    stack = [data]
    for _ in range(MAX_EXTRACT_NODES):
        if not stack:
            break
        item = stack.pop()
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return result


def _extract_tool_info(payload):
    """Extract tool name and tool input from payload."""
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not tool_name and isinstance(payload.get("toolCall"), dict):
        call = payload["toolCall"]
        tool_name = call.get("name")
        tool_input = call.get("args")
    return str(tool_name or ""), tool_input


def _path_operands(text):
    """Yield the literal input, its shell words and any values attached with '='."""
    yield text
    pattern = r""""[^"\n]*"|'[^'\n]*'|[^\s'";&|<>()]+"""
    for _, match in zip(range(SESSION_INPUT_LIMIT), re.finditer(pattern, text)):
        word = match.group().strip("\"'")
        yield word
        _, separator, value = word.partition("=")
        if separator and value:
            yield value


def _path_matches(resolved_path_str, text, cwd=None, budget=None):
    """Resolve literal operands against their working directory without execution."""
    try:
        worktree = Path(resolved_path_str).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    for _, candidate in zip(range(SESSION_INPUT_LIMIT), _path_operands(text)):
        if budget is not None:
            budget.timeout(1)
        path = Path(candidate)
        if not path.is_absolute():
            if cwd is None:
                continue
            path = Path(cwd) / path
        try:
            path.resolve().relative_to(worktree)
            return True
        except (OSError, RuntimeError, ValueError):
            continue
    return False


def _is_worktree_touched(
    resolved, tool_name, tool_input, strings, *, cwd=None, budget=None
):
    """Whether worktree was touched by tool invocation."""
    if tool_name == "EnterWorktree" and isinstance(tool_input, dict):
        target = tool_input.get("name") or tool_input.get("path")
        if isinstance(target, str) and target.strip() in (resolved.name, str(resolved)):
            return True
    path_str = str(resolved)
    return any(_path_matches(path_str, s, cwd, budget) for s in strings)


def _read_session_record(record_file, check=None):
    """Preserve resolvable owners; only missing worktrees may be discarded."""
    try:
        with record_file.open("rb") as stream:
            raw = stream.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            return None
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) > MAX_WORKTREES:
            return None
        if not all(isinstance(path, str) and Path(path).is_absolute() for path in data):
            return None
        return _resolve_session_paths(data, check)
    except (OSError, RuntimeError, ValueError):
        return None


def _resolve_session_paths(data, check):
    """Resolve each bounded owner path while allowing removed worktrees to disappear."""
    paths = set()
    for path in data[:MAX_WORKTREES]:
        if check is not None:
            check()
        try:
            paths.add(str(Path(path).resolve(strict=True)))
        except FileNotFoundError:
            continue  # Removed worktrees no longer participate in ownership.
    return paths


def _write_session_record(sessions_dir, record_file, paths, check=None):
    """Atomically write sorted bounded worktree paths to session record."""
    from common import HookBudget

    if check is not None:
        _replace_session_record(sessions_dir, record_file, paths, check)
        return
    budget = HookBudget(SESSION_LOCK_MAX_HOLD_SECONDS)
    with _session_update_lock(sessions_dir, record_file, budget) as held:
        _replace_session_record(sessions_dir, record_file, paths, held)
    _prune_session_records(sessions_dir, record_file, budget)


def _replace_session_record(sessions_dir, record_file, paths, check):
    """Publish bounded ownership while the caller holds the record lock."""
    sorted_paths = sorted(paths) if len(paths) <= MAX_WORKTREES else None
    payload = json.dumps(sorted_paths).encode("utf-8")
    if len(payload) > MAX_RECORD_BYTES:
        raise ValueError("checkpoint session record exceeds byte bound")
    tmp = None
    try:
        check()
        with tempfile.NamedTemporaryFile(dir=sessions_dir, delete=False) as handle:
            tmp = Path(handle.name)
            handle.write(payload)
        check()
        os.replace(tmp, record_file)
        tmp = None
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def _prune_session_record(record_file, cutoff, budget):
    """Remove one expired regular record while holding its writer lock."""
    lock = record_file.with_suffix(".lock")
    started = time.monotonic()
    token = _acquire_session_lock(lock)
    if not token:
        return  # An in-flight writer owns this record; a later write retries cleanup.
    try:
        try:
            info = record_file.lstat()
        except FileNotFoundError:
            return  # Another cleanup already removed this record.
        if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
            _check_session_lock(lock, token, budget, started)
            record_file.unlink(missing_ok=True)
    finally:
        _release_session_lock(lock, token)


def _prune_session_records(sessions_dir, current_record, budget=None):
    """Bound each sweep; age equal to the shared activity window remains fresh."""
    from common import HookBudget

    if budget is None:
        budget = HookBudget(SESSION_LOCK_MAX_HOLD_SECONDS)
    cutoff = time.time() - WORKTREE_ACTIVITY_WINDOW
    with os.scandir(sessions_dir) as records:
        for _ in range(MAX_SESSION_RECORDS):
            budget.timeout(SESSION_LOCK_MAX_HOLD_SECONDS)
            entry = next(records, None)
            if entry is None:
                break
            path = Path(entry.path)
            if path != current_record and entry.name.endswith(".json"):
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue  # Another cleanup already removed this entry.
                if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                    _prune_session_record(path, cutoff, budget)


def _reclaim_session_lock(lock):
    """Atomically claim the observed stale token; another owner has a different name."""
    try:
        with os.scandir(lock) as entries:
            entry = next(entries, None)
            owner = entry.name if entry is not None else None
            if next(entries, None) is not None:
                return False
        info = lock.lstat()
        age = time.time() - info.st_mtime
        if not stat.S_ISDIR(info.st_mode) or age <= SESSION_LOCK_STALE_SECONDS:
            return False
        if owner is not None:
            if not owner.startswith("owner-"):
                return False
            tombstone = lock.with_name(f"{lock.name}.{owner}.reclaimed")
            os.rename(lock / owner, tombstone)
            tombstone.unlink()
        lock.rmdir()  # Atomic for empty legacy locks too; a new token prevents removal.
        return True
    except OSError:
        return False


def _try_session_guard(lock, cleanup):
    """Hold the shard until release or process exit, including during suspension."""
    shard = session_hash_for(lock.name)[0]
    guard = lock.with_name(f".session-guard-{shard}")
    if os.name != "nt":
        return _try_posix_guard(guard, shard, cleanup)
    # The kernel deletes the exclusive name when its last handle closes.
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_TEMPORARY
        fd = os.open(guard.with_suffix(".tmp"), flags, 0o600)
    except FileExistsError:
        return False
    cleanup.callback(os.close, fd)
    return True


def _try_posix_guard(guard, shard, cleanup):
    """Lock the named inode and unlink it under the lock on normal release."""
    mutex = _SESSION_GUARDS[int(shard, 16)]
    if not mutex.acquire(blocking=False):
        return False
    cleanup.callback(mutex.release)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(guard, flags, 0o600)
    cleanup.callback(os.close, fd)
    try:
        os.lockf(fd, os.F_TLOCK, 1)
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EAGAIN):
            return False
        raise
    # An opener can pause before lockf while a previous holder unlinks its inode.
    # Only the holder of the still-linked inode may proceed or remove the name.
    try:
        current = guard.lstat()
    except FileNotFoundError:
        return False
    if not os.path.samestat(os.fstat(fd), current):
        return False
    cleanup.callback(guard.unlink)
    return True


def _acquire_session_lock(lock):
    """Hold the kernel guard while acquiring and using the legacy owner token."""
    with contextlib.ExitStack() as cleanup:
        if not _try_session_guard(lock, cleanup):
            return None
        token = _acquire_owner_token(lock)
        return (token, cleanup.pop_all()) if token else None


def _acquire_owner_token(lock):
    """Return a unique owner token, or None when another writer holds the lock."""
    token = "owner-" + os.urandom(16).hex()
    with tempfile.TemporaryDirectory(prefix=f".{lock.name}.", dir=lock.parent) as raw:
        staged = Path(raw)
        (staged / token).write_text(token, encoding="ascii")
        if lock.exists() and not _reclaim_session_lock(lock):
            return None
        try:
            os.rename(staged, lock)  # Publish directory and token together.
        except OSError as error:
            if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            return None
    return token


def _check_session_lock(lock, token, budget, started):
    """Refuse work after ownership loss, caller deadline or maximum hold time."""
    from common import HookError

    budget.timeout(SESSION_LOCK_MAX_HOLD_SECONDS)
    if time.monotonic() - started >= SESSION_LOCK_MAX_HOLD_SECONDS:
        raise HookError("checkpoint session lock maximum hold time spent")
    if not (lock / token[0]).is_file():
        raise HookError("checkpoint session lock ownership lost")


def _release_session_lock(lock, token):
    """Keep the kernel lock until the directory token has also been released."""
    owner, guard = token
    with guard:
        _release_owner_token(lock, owner)


def _release_owner_token(lock, token):
    """Remove only our token; a replacement owner's nonempty directory survives."""
    from common import HookError

    try:
        (lock / token).unlink()
    except FileNotFoundError as error:
        raise HookError("checkpoint session lock ownership lost") from error
    try:
        lock.rmdir()
    except FileNotFoundError:
        pass  # A contender removed the empty directory after our token was removed.
    except OSError as error:
        if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise


@contextlib.contextmanager
def _session_update_lock(sessions_dir, record_file, budget):
    """Serialize complete read/merge/write transactions across hook processes."""
    from common import HookError

    sessions_dir.mkdir(parents=True, exist_ok=True)
    lock = record_file.with_suffix(".lock")
    token = None
    for _ in range(501):
        budget.timeout(0.01)
        started = time.monotonic()
        token = _acquire_session_lock(lock)
        if token:
            break
        time.sleep(budget.timeout(0.01))
    if not token:
        raise HookError("checkpoint session update lock timed out")
    try:

        def check():
            """Require current ownership and time remaining on both deadlines."""
            _check_session_lock(lock, token, budget, started)

        check()
        yield check
        check()
    finally:
        _release_session_lock(lock, token)


def _update_session_record(sessions_dir, record_file, touched, budget):
    """Keep every previously recorded owner when tools and Stop race."""
    from common import HookError

    with _session_update_lock(sessions_dir, record_file, budget) as check:
        exists = record_file.is_file()
        existing = _read_session_record(record_file, check) if exists else set()
        if exists and (existing is None or touched <= existing):
            check()
            os.utime(record_file, None, follow_symlinks=False)
        else:
            _write_session_record(sessions_dir, record_file, existing | touched, check)
    try:
        _prune_session_records(sessions_dir, record_file, budget)
    except (HookError, OSError) as error:
        sys.stderr.write(f"Praetor: checkpoint session cleanup skipped: {error}\n")


def ensure_session_record(root, session_hash, budget):
    """Initialize under the same interprocess lock as tool updates."""
    common_dir = _git_common_dir(root, budget)
    sessions_dir = common_dir / "praetor-checkpoint" / "sessions"
    record_file = sessions_dir / f"{session_hash}.json"
    _update_session_record(sessions_dir, record_file, set(), budget)


def record_tool_worktrees(payload, root, budget):
    """Record any worktree paths touched by tool event."""
    session_id = extract_session_id(payload)
    if not session_id:
        return
    session_hash = session_hash_for(session_id)
    tool_name, tool_input = _extract_tool_info(payload)
    if not tool_input:
        ensure_session_record(root, session_hash, budget)
        return
    strings = _extract_strings(tool_input)
    cwd = _tool_working_directory(payload, tool_input, root)
    common_dir = _git_common_dir(root, budget)
    sessions_dir = common_dir / "praetor-checkpoint" / "sessions"
    record_file = sessions_dir / f"{session_hash}.json"

    worktrees = _listed_worktrees(root, budget)
    touched = set()
    for entry in worktrees:
        try:
            resolved = Path(entry["path"]).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved == root:
            continue
        if _is_worktree_touched(
            resolved, tool_name, tool_input, strings, cwd=cwd, budget=budget
        ):
            touched.add(str(resolved))
    _update_session_record(sessions_dir, record_file, touched, budget)


def prepare_checkpoint_session(payload, root, budget, stopping):
    """Prepare one shared ownership record and return its hashed identity."""
    session_id = extract_session_id(payload)
    if not session_id:
        return ""
    session_hash = session_hash_for(session_id)
    if stopping:
        ensure_session_record(root, session_hash, budget)
    else:
        record_tool_worktrees(payload, root, budget)
    return session_hash


def _tool_working_directory(payload, tool_input, root):
    """Use the tool working directory when present, otherwise the event checkout."""
    event_cwd = payload.get("cwd") or str(root)
    if not isinstance(event_cwd, str):
        event_cwd = str(root)
    if isinstance(tool_input, dict):
        tool_cwd = tool_input.get("workdir") or tool_input.get("cwd") or event_cwd
    else:
        tool_cwd = event_cwd
    if not isinstance(tool_cwd, str):
        return root
    path = Path(tool_cwd)
    return path if path.is_absolute() else Path(event_cwd) / path
