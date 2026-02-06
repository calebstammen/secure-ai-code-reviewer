from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path
from typing import Iterable, List, Set


LANG_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
}


def _git_ls_files(root: Path) -> List[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    files = []
    for line in result.stdout.splitlines():
        if line.strip():
            files.append(root / line.strip())
    return files


def discover_files(
    root: Path, include_globs: Iterable[str], exclude_globs: Iterable[str]
) -> List[Path]:
    include = list(include_globs)
    exclude = list(exclude_globs)
    candidates: List[Path]
    git_files = _git_ls_files(root)
    if git_files:
        candidates = git_files
    else:
        candidates = [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]

    filtered: List[Path] = []
    seen: Set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        rel = path.relative_to(root).as_posix()
        if include and not any(fnmatch.fnmatch(rel, pat) for pat in include):
            continue
        if exclude and any(fnmatch.fnmatch(rel, pat) for pat in exclude):
            continue
        filtered.append(path)
    return filtered


def detect_language(path: Path) -> str:
    return LANG_EXTENSIONS.get(path.suffix.lower(), "unknown")
