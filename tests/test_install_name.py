"""Regression guards for the distribution name and the documented install lines.

The distribution name is read from ``[project] name`` in pyproject.toml, never
hardcoded, so a future rename cannot leave the docs pointing at a package that
does not exist. Two facts are pinned here:

1. Nothing is published on PyPI yet, so the docs must install from git. A bare
   ``pip install <name>`` line in the docs is a 404 for the reader.
2. The name ``depscan`` on PyPI belongs to an unrelated third-party project
   (linkedlist771/depscan, "A fast Python dependency analyzer that automatically
   discovers and extracts third-party imports"), so it must never be offered as
   an install target -- not now, not in any future commit. That name belongs to
   another author permanently, and installing it hands the reader a completely
   different project that happens to share our name. It stays in
   FORBIDDEN_TARGETS even after this project is published.

This is the same subject matter as the foreign package, which makes the
collision the worst kind: a reader who types the name they see in the URL
believes they are installing this tool and gets a lookalike with a different
author instead.

Note the repo name and the distribution name differ: the repo is ``depscan``
(also the console script, the command the user types), the distribution is
``depscan-py``.

Only the first fact flips on publication. Publishing is gated on creating the
project on PyPI and registering a trusted publisher; once
``pip install depscan-py`` resolves, the git line becomes unnecessary and the
bare install of *that* name becomes correct. Flip ``PUBLISHED`` in that same
commit -- do not leave a guard that forces one of two wrong states. The
``depscan`` entry does not move with the flag.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Flip to True in the same commit that restores the PyPI install line, once
# https://pypi.org/pypi/depscan-py/json answers 200.
PUBLISHED = False

# Every tracked surface a reader can copy an install line out of.
DOC_SURFACES = (
    "README.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "action.yml",
    ".pre-commit-hooks.yaml",
    "Dockerfile",
    "SECURITY.md",
    "docs/API.md",
)

_PYPROJECT = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
DIST_NAME: str = _PYPROJECT["project"]["name"]

# The repository name -- which is also the console script name, and the name of
# the third-party PyPI project.
REPO_NAME = "depscan"

EXPECTED_INSTALL = (
    f"pip install {DIST_NAME}"
    if PUBLISHED
    else f"pip install git+https://github.com/yunaremaia/{REPO_NAME}.git"
)

# Install targets that must never appear. While unpublished, a bare
# `pip install depscan-py` 404s just like the short name does; the short name
# fails worse, by silently installing another author's project.
#
# REPO_NAME is permanent and is NOT gated on PUBLISHED: `depscan` on PyPI is
# linkedlist771's project and will never be this one, so no future publication
# makes it a valid install target here.
FORBIDDEN_TARGETS = {REPO_NAME} | (set() if PUBLISHED else {DIST_NAME})

# `pip install`, `pip3 install`, `uv tool install`, `uv pip install` and
# `python -m pip install`, plus everything after them on the line.
INSTALL_COMMAND = re.compile(
    r"(?:uv\s+(?:tool|pip)|pip3?|python3?\s+-m\s+pip)\s+install(?P<args>[^\n]*)",
    re.MULTILINE,
)

# A PEP 508 requirement: a bare name, optional extras, optional version spec.
#
# The negative lookahead `(?![\w.-])` is load-bearing. A plain substring check
# for "pip install depscan" is True for "pip install depscan-py", so the naive
# grep would flag the very line it is meant to protect. Anchoring the name and
# refusing to stop mid-token keeps the two apart.
#
# This also rejects, for free, every target that is not a bare name: a `git+`
# URL fails the spec part at the `+`, and `.` / `.[dev]` never start with an
# alphanumeric.
REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?![\w.-])"
    r"(?P<spec>\[[^\]]*\])?(?:[<>=!~].*)?$"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _requirement_name(token: str) -> str | None:
    """Return the distribution name a pip target token names, if it names one."""
    match = REQUIREMENT.match(token)
    return match.group("name") if match else None


def install_targets(line: str) -> list[str]:
    """Return the distribution names pip would be handed by an install command."""
    names = []
    for command in INSTALL_COMMAND.finditer(line):
        try:
            tokens = shlex.split(command.group("args"))
        except ValueError:
            tokens = command.group("args").split()
        for token in tokens:
            if token.startswith("-"):  # -e, --upgrade, -r, --no-cache-dir ...
                continue
            name = _requirement_name(token)
            if name is not None:
                names.append(name)
    return names


def bare_install_lines(text: str) -> list[str]:
    """Return every line in *text* that installs a forbidden bare target.

    Only the tokens pip would actually receive are considered, so options and
    their values never register: a legitimate `git clone` + `pip install -e .`
    from-source block cannot show up as an offender.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if FORBIDDEN_TARGETS.intersection(install_targets(line))
    ]


def doc_surfaces() -> list[tuple[str, Path]]:
    """The DOC_SURFACES that exist in this checkout."""
    return [(name, REPO_ROOT / name) for name in DOC_SURFACES if (REPO_ROOT / name).exists()]


class TestDocsInstallFromGitWhileUnpublished:
    """The expected install line is asserted first, so a failure names the fix."""

    def test_readme_carries_the_expected_install_line(self):
        assert EXPECTED_INSTALL in _read(README), f"README must carry `{EXPECTED_INSTALL}`"


class TestNoBarePyPIInstallAnywhere:
    def test_surfaces_were_found(self):
        """Guard the guard: an empty surface list would assert nothing."""
        found = doc_surfaces()
        assert found, f"none of {DOC_SURFACES} exists -- the surface list is stale"
        assert "README.md" in [name for name, _ in found]
        assert "CONTRIBUTING.md" in [name for name, _ in found], (
            "CONTRIBUTING.md carries the from-source block, so a stale surface "
            "list would be a false GREEN"
        )

    def test_no_surface_installs_a_forbidden_bare_name(self):
        offenders = {
            name: lines[:5] for name, path in doc_surfaces() if (lines := bare_install_lines(_read(path)))
        }
        offenders = {name: lines for name, lines in offenders.items() if lines}
        assert not offenders, (
            f"these files tell readers to `pip install` {sorted(FORBIDDEN_TARGETS)}, which on "
            f"PyPI is not this project. Use `{EXPECTED_INSTALL}`. "
            f"Offending files and lines: {offenders}"
        )

    def test_no_pypi_badge_while_unpublished(self):
        """A PyPI badge renders "not found" for a package that is not on PyPI."""
        badges = [line for line in _read(README).splitlines() if "img.shields.io/pypi" in line]
        assert not badges, f"PyPI badge would render broken: {badges}"


class TestTargetParsing:
    """Literal inputs, so editing a constant above cannot make these pass."""

    def test_git_install_is_not_a_bare_name(self):
        line = "pip install git+https://github.com/yunaremaia/depscan.git"
        assert install_targets(line) == []
        assert bare_install_lines(line) == []

    def test_short_name_is_a_bare_name(self):
        assert install_targets("pip install depscan") == ["depscan"]
        assert bare_install_lines("pip install depscan")

    def test_uv_and_pip3_variants_are_covered(self):
        for line in ("uv tool install depscan", "uv pip install depscan", "pip3 install depscan"):
            assert bare_install_lines(line), line

    def test_unrelated_packages_are_not_caught(self):
        for line in (
            "pip install pre-commit",
            "python -m pip install --upgrade pip",
            "python -m pip install build twine",
        ):
            assert install_targets(line) and not bare_install_lines(line), line

    def test_from_source_blocks_are_not_caught(self):
        """`git clone` + `pip install -e .` is a legitimate install, not a lie."""
        for line in (
            "pip install -e .",
            'pip install -e ".[dev]"',
            "pip install -r requirements.txt",
            "RUN pip install --no-cache-dir .",
        ):
            assert not bare_install_lines(line), line

    def test_bare_distribution_name_is_forbidden_while_unpublished(self):
        """`-py` is still a bare install target, and it still 404s."""
        line = "pip install depscan-py"
        assert install_targets(line) == ["depscan-py"]
        assert bool(bare_install_lines(line)) is not PUBLISHED


class TestTheRegexIsNotANaiveSubstringCheck:
    def test_a_substring_check_could_not_separate_the_two_names(self):
        """Documents the trap this guard exists to avoid.

        The needle is built from the repo name, so the check reads as the naive
        grep it warns about rather than as two unrelated literals.
        """
        needle = f"pip install {REPO_NAME}"
        assert needle in f"{needle}-py"

    def test_the_requirement_parser_does_separate_them(self):
        assert _requirement_name("depscan-py") == "depscan-py"
        assert _requirement_name("depscan") == "depscan"
        assert _requirement_name("git+https://github.com/yunaremaia/depscan.git") is None


class TestTheSquattedNameStaysForbiddenForever:
    """The one rule that does not move when PUBLISHED flips."""

    def test_repo_name_is_forbidden_regardless_of_published(self):
        assert REPO_NAME in FORBIDDEN_TARGETS, (
            f"`{REPO_NAME}` is another author's PyPI name; it must stay forbidden "
            "after publication too"
        )

    def test_repo_name_is_never_the_chosen_distribution_name(self):
        """If these ever match, the rename was reverted and the hijack is back."""
        assert DIST_NAME != REPO_NAME, (
            f"distribution name {DIST_NAME!r} collides with the third-party "
            f"PyPI project {REPO_NAME!r}"
        )

    def test_repo_name_is_forbidden_in_a_hypothetical_published_world(self):
        """Assert the post-publication behaviour directly, flag included."""
        published_targets = {REPO_NAME} | (set() if PUBLISHED else {DIST_NAME})
        offenders = [
            line
            for line in ("pip install depscan", "pip install depscan-py")
            if published_targets.intersection(install_targets(line))
        ]
        assert "pip install depscan" in offenders
        assert ("pip install depscan-py" in offenders) is not PUBLISHED


class TestReadmeDisclosesTheNameSituation:
    """A reader who sees `depscan-py` deserves to know what is going on."""

    def test_short_name_is_disclosed_as_foreign(self):
        text = _read(README).lower()
        assert REPO_NAME in text
        assert "pypi" in text
        assert any(
            phrase in text for phrase in ("different author", "another author", "unrelated", "taken")
        ), "README must say the depscan PyPI name belongs to another project"

    def test_unpublished_state_is_disclosed(self):
        """Otherwise a git URL in the install block reads as a mistake."""
        text = _read(README).lower()
        assert any(
            phrase in text for phrase in ("not published", "not yet on pypi", "not yet published")
        ), "README must state the project is not on PyPI yet, so the git URL is expected"


class TestPreCommitHookDoesNotInstallTheForeignPackage:
    """`additional_dependencies` is a pip requirement, so it hijacks the same way.

    This surface carries no `pip install` token, so `bare_install_lines` cannot
    see it, and the hijack is invisible to the scan above. Left as
    `depscan>=0.1.0`, pre-commit installs linkedlist771's package and runs
    *its* `depscan scan` on every commit.
    """

    PRE_COMMIT = REPO_ROOT / ".pre-commit-hooks.yaml"

    def _requirements(self) -> list[str]:
        import yaml

        hooks = yaml.safe_load(_read(self.PRE_COMMIT))
        return [d for hook in hooks for d in hook.get("additional_dependencies", [])]

    def test_hook_declares_no_bare_name_from_pypi(self):
        """Only a bare name is hijackable; a direct reference is not.

        `depscan>=0.1.0` sends pre-commit to PyPI and hands it another
        author's package. `depscan-py @ git+...` names the same distribution
        but pins it to a source that is unambiguously this repository, so the
        name alone must not condemn the requirement. What is condemned is a
        requirement that resolves through the index.
        """
        offenders = [
            req
            for req in self._requirements()
            if _requirement_name(req) in FORBIDDEN_TARGETS
        ]
        assert not offenders, (
            f"pre-commit would resolve {offenders} through PyPI, where the name "
            f"belongs to another author. Point the hook at this repository."
        )

    def test_hook_never_installs_the_foreign_name(self):
        """The squatted name is forbidden here regardless of how it is pinned."""
        offenders = [
            req
            for req in self._requirements()
            if _requirement_name(req.split(" @ ")[0].strip()) == REPO_NAME
        ]
        assert not offenders, f"pre-commit installs the foreign package: {offenders}"

    def test_hook_installs_this_repository(self):
        """A direct reference keeps the hook honest until the name is published."""
        assert any("git+https://github.com/yunaremaia/depscan.git" in r for r in self._requirements()), (
            "the pre-commit hook must install depscan from this repository"
        )

    def test_hook_id_and_entry_stay_the_console_script(self):
        """Only the distribution moves; the hook contract does not."""
        import yaml

        hook = yaml.safe_load(_read(self.PRE_COMMIT))[0]
        assert hook["id"] == REPO_NAME
        assert hook["entry"].split()[0] == REPO_NAME


class TestPackaging:
    def test_console_script_name_is_the_repo_name(self):
        """Only the distribution moves; the command a user types does not."""
        assert REPO_NAME in _PYPROJECT["project"]["scripts"], (
            f"console script must stay `{REPO_NAME}`; only the distribution "
            "carries the `-py` suffix"
        )

    def test_import_module_is_unchanged(self):
        packages = _PYPROJECT["tool"]["setuptools"]["packages"]["find"]["where"]
        assert packages == ["src"], f"import root must stay `src`, got {packages}"

    def test_console_script_target_is_importable(self):
        """The entry point must resolve against the built wheel, not the source tree.

        The distribution rename moved the name that `click.version_option`
        looks up in the installed metadata. It used to be hardcoded as
        `package_name="depscan"`, which no longer exists once the distribution
        is called `depscan-py`: `--version` raised RuntimeError because the
        import name then mapped to more than one installed distribution. The
        version is now read from the package's own `__version__` instead, so
        this entry point must keep resolving inside the packaged tree.
        """
        target = _PYPROJECT["project"]["scripts"][REPO_NAME]
        module_path, _, attr = target.partition(":")

        # setuptools `where = ["src"]` installs the `depscan` package from
        # `src/`, so `src/` is the directory that goes on sys.path.
        packaged_root = REPO_ROOT / _PYPROJECT["tool"]["setuptools"]["packages"]["find"]["where"][0]
        top_level = module_path.split(".")[0]
        assert packaged_root.joinpath(top_level).is_dir(), (
            f"console script imports {top_level!r}, which is not packaged from {packaged_root}"
        )

        resolved = packaged_root / Path(*module_path.split(".")).with_suffix(".py")
        assert resolved.exists(), f"console script module not in wheel: {module_path} ({resolved})"

        source = resolved.read_text(encoding="utf-8")
        assert re.search(rf"^def {re.escape(attr)}\b", source, re.MULTILINE), (
            f"{target} does not define {attr}() in {resolved.name}"
        )

    def test_version_flag_does_not_depend_on_the_distribution_name(self):
        """`--version` must not look up the old, colliding distribution name.

        `click.version_option(package_name=...)` resolves through the *installed
        distribution* metadata, so pinning it to the PyPI name would couple the
        CLI to a name this project deliberately does not own. Reading
        `__version__` off the package keeps `--version` working under any
        distribution name.
        """
        source = (REPO_ROOT / "src" / REPO_NAME / "cli.py").read_text(encoding="utf-8")
        assert "package_name=" not in source, (
            "cli.py must not pin click's version_option to a distribution name; "
            "use version=__version__ so the CLI is independent of the PyPI name"
        )
        assert re.search(r"@click\.version_option\(", source), "the --version flag must remain"


@pytest.mark.parametrize("line", ["pip install pre-commit", "pip install -e ."])
def test_parser_noise_is_not_reported(line):
    """Explicitly assert the two shapes that produced false positives before."""
    assert bare_install_lines(line) == []
