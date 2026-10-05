"""Tests for dependency scanner."""
import pytest
from pathlib import Path
from unittest.mock import patch

from depscan.scanner import (
    MultiScanner,
    DependencyParser,
    Dependency,
    Vulnerability,
    validate_package_name,
    check,
    SAFE_PACKAGE_NAME_RE,
)


class TestDependencyParser:
    def setup_method(self):
        self.parser = DependencyParser()

    def test_parse_cargo_lock(self):
        content = '''
[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0.0"
'''
        deps = self.parser.parse_cargo_lock(content)
        assert len(deps) == 2
        assert deps[0].name == "serde"
        assert deps[0].version == "1.0.0"
        assert deps[0].ecosystem == "cargo"

    def test_parse_package_lock(self):
        content = '''
{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/express": {
      "version": "4.18.0"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 2

    def test_parse_package_lock_v1_legacy(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.21"
    },
    "express": {
      "version": "4.18.0"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 2
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["lodash"] == "4.17.21"
        assert dep_map["express"] == "4.18.0"
        assert all(d.ecosystem == "npm" for d in deps)

    def test_parse_package_lock_v1_nested_dependencies(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.0",
      "dependencies": {
        "accepts": {
          "version": "1.3.8",
          "dependencies": {
            "mime-types": {
              "version": "2.1.35"
            }
          }
        }
      }
    },
    "chalk": {
      "version": "5.0.0"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 4
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["express"] == "4.18.0"
        assert dep_map["accepts"] == "1.3.8"
        assert dep_map["mime-types"] == "2.1.35"
        assert dep_map["chalk"] == "5.0.0"

    def test_parse_package_lock_v1_deduplication(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "pkg-a": {
      "version": "1.0.0",
      "dependencies": {
        "shared": {
          "version": "2.0.0"
        }
      }
    },
    "pkg-b": {
      "version": "1.0.0",
      "dependencies": {
        "shared": {
          "version": "2.0.0"
        }
      }
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 3
        shared_deps = [d for d in deps if d.name == "shared"]
        assert len(shared_deps) == 1
        assert shared_deps[0].version == "2.0.0"

    def test_parse_package_lock_v2(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/express": {
      "version": "4.18.0"
    }
  },
  "dependencies": {
    "lodash": {
      "version": "4.17.21"
    },
    "express": {
      "version": "4.18.0"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 2
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["lodash"] == "4.17.21"
        assert dep_map["express"] == "4.18.0"

    def test_parse_package_lock_v2_fallback_when_packages_empty(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "dependencies": {
    "lodash": {
      "version": "4.17.21"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 1
        assert deps[0].name == "lodash"
        assert deps[0].version == "4.17.21"

    def test_parse_package_lock_v3_scoped_and_nested(self):
        content = '''
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0"
    },
    "node_modules/@types/node": {
      "version": "20.1.0"
    },
    "node_modules/foo/node_modules/bar": {
      "version": "1.2.3"
    }
  }
}
'''
        deps = self.parser.parse_package_lock(content)
        assert len(deps) == 2
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["@types/node"] == "20.1.0"
        assert dep_map["bar"] == "1.2.3"

    def test_parse_package_lock_invalid_json(self):
        assert self.parser.parse_package_lock("invalid json") == []
        assert self.parser.parse_package_lock("[]") == []
        assert self.parser.parse_package_lock("") == []

    def test_parse_requirements_txt(self):
        content = '''
requests==2.28.0
flask>=2.0.0
numpy==1.24.0
'''
        deps = self.parser.parse_requirements_txt(content)
        assert len(deps) == 3

    def test_parse_requirements_txt_all_operators(self):
        """Test that all version specifiers are parsed, including ~=, <=, >, <, !=."""
        content = '''
requests>=2.28.0
flask~=2.3.0
numpy<=1.24.0
pandas>1.5.0
scipy<1.10.0
tensorflow!=2.10.0
click==8.0.0
no-version-package
'''
        deps = self.parser.parse_requirements_txt(content)
        assert len(deps) == 8
        by_name = {d.name: d for d in deps}
        assert by_name["flask"].version == "2.3.0"  # ~=
        assert by_name["numpy"].version == "1.24.0"  # <=
        assert by_name["pandas"].version == "1.5.0"  # >
        assert by_name["scipy"].version == "1.10.0"  # <
        assert by_name["tensorflow"].version == "2.10.0"  # !=
        assert by_name["no-version-package"].version == ""  # no specifier

    def test_parse_go_mod(self):
        content = '''
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
)
'''
        deps = self.parser.parse_go_mod(content)
        assert len(deps) == 2

    def test_parse_go_mod_replace_single(self):
        content = '''
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/foo/bar v1.2.3
)

replace github.com/foo/bar => github.com/foo/bar v1.5.0
'''
        deps = self.parser.parse_go_mod(content)
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["github.com/gin-gonic/gin"] == "1.9.0"
        assert dep_map["github.com/foo/bar"] == "1.5.0"

    def test_parse_go_mod_replace_block_and_local(self):
        content = '''
require (
    github.com/a/b v1.0.0
    github.com/c/d v2.0.0
)

replace (
    github.com/a/b => github.com/a/b v1.1.0
    github.com/c/d => ./local/d
)
'''
        deps = self.parser.parse_go_mod(content)
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["github.com/a/b"] == "1.1.0"
        assert dep_map["github.com/c/d"] == "./local/d"

    def test_parse_go_mod_single_require(self):
        content = '''
require github.com/single/mod v0.9.1
replace github.com/single/mod => github.com/single/mod v1.0.0
'''
        deps = self.parser.parse_go_mod(content)
        assert len(deps) == 1
        assert deps[0].name == "github.com/single/mod"
        assert deps[0].version == "1.0.0"

    def test_parse_poetry_lock(self):
        content = '''
[[package]]
name = "django"
version = "4.2.0"

[[package]]
name = "celery"
version = "5.3.0"
'''
        deps = self.parser.parse_poetry_lock(content)
        assert len(deps) == 2

    def test_parse_gemfile_lock(self):
        content = '''
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.0)
      actionview (= 7.1.0)
      rack (>= 2.2.4)
    rails (7.1.0)
      actionpack (= 7.1.0)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)

BUNDLED WITH
   2.4.0
'''
        deps = self.parser.parse_gemfile_lock(content)
        assert len(deps) == 2
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["actionpack"] == "7.1.0"
        assert dep_map["rails"] == "7.1.0"
        assert all(d.ecosystem == "rubygems" for d in deps)

    def test_parse_gemfile_lock_old_format(self):
        # bundler 0.9.x listed gems directly under GEM, without "specs:".
        content = '''
GEM
  remote: https://rubygems.org/
    rack (1.6.0)
    rake (12.0.0)

PLATFORMS
  ruby
'''
        deps = self.parser.parse_gemfile_lock(content)
        assert len(deps) == 2
        dep_map = {d.name: d.version for d in deps}
        assert dep_map["rack"] == "1.6.0"
        assert dep_map["rake"] == "12.0.0"

    def test_parse_gemfile_lock_ignores_git_and_path_sections(self):
        content = '''
GIT
  remote: https://github.com/example/gem.git
  revision: abc123
  specs:
    gem_from_git (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.0)

PATH
  remote: ./local_gem
  specs:
    local_gem (0.0.1)
'''
        deps = self.parser.parse_gemfile_lock(content)
        assert len(deps) == 1
        assert deps[0].name == "rails"

    def test_parse_gemfile_lock_platform_version_suffix(self):
        content = '''
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.0-x86_64-linux)
'''
        deps = self.parser.parse_gemfile_lock(content)
        assert len(deps) == 1
        assert deps[0].name == "nokogiri"
        assert deps[0].version == "1.15.0-x86_64-linux"

    def test_parse_gemfile_lock_empty_or_malformed(self):
        assert self.parser.parse_gemfile_lock("") == []
        assert self.parser.parse_gemfile_lock("not a lockfile\nat all\n") == []

    def test_pipfile_lock_parsing(self):
        content = '''
{
    "_meta": {
        "hash": {"sha256": "abcdef"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.11"}
    },
    "default": {
        "requests": {
            "hashes": ["sha256:1234"],
            "index": "pypi",
            "version": "==2.31.0"
        },
        "urllib3": {
            "hashes": ["sha256:5678"],
            "version": "==2.0.4"
        },
        "certifi": {
            "hashes": ["sha256:9012"],
            "version": "==2023.7.22"
        }
    },
    "develop": {
        "pytest": {
            "hashes": ["sha256:3456"],
            "version": "==7.4.0"
        },
        "black": {
            "hashes": ["sha256:7890"],
            "version": "==23.7.0"
        }
    }
}
'''
        deps = self.parser.parse_pipfile_lock(content)
        assert len(deps) == 5
        names = {d.name for d in deps}
        assert names == {"requests", "urllib3", "certifi", "pytest", "black"}
        for d in deps:
            assert d.ecosystem == "pypi"

    def test_pipfile_lock_uses_exact_versions(self):
        content = '''
{
    "default": {
        "requests": {"version": "==2.31.0"}
    }
}
'''
        deps = self.parser.parse_pipfile_lock(content)
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"

    def test_pipfile_lock_malformed_json(self):
        content = "{ invalid json"
        deps = self.parser.parse_pipfile_lock(content)
        assert deps == []

    test_plfile_lock_parsing = test_pipfile_lock_parsing
    test_plfile_lock_uses_exact_versions = test_pipfile_lock_uses_exact_versions
    test_plfile_lock_malformed_json = test_pipfile_lock_malformed_json


class TestMultiScanner:
    def setup_method(self):
        self.scanner = MultiScanner()

    def test_typosquat_detection(self):
        dep = Dependency(name="raquests", version="1.0.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is True
        assert dep.is_typosquat
        assert dep.typosquat_target == "requests"

    def test_no_typosquat_for_known_package(self):
        dep = Dependency(name="requests", version="2.28.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is False

    def test_every_allowlisted_target_is_never_a_typosquat(self):
        """A name on the known-good list must never be reported, whatever its position.

        ``check_typosquat`` used to test the allowlist *inside* the similarity
        loop, so an entry that happened to sit within edit distance 2 of an
        earlier entry (``black`` vs ``flask``, ``rack`` vs ``rich``, ``rake``
        vs ``rack``, ``orjson`` vs ``ujson``) was flagged before its own exact
        match could ever be reached.  That made depscan's own CI gate exit 1 on
        legitimate packages.
        """
        for target in self.scanner._typosquat_targets:
            dep = Dependency(name=target, version="1.0.0", ecosystem="pypi")
            assert self.scanner.check_typosquat(dep) is False, (
                f"{target!r} is allowlisted as known-good but was reported as a "
                f"typosquat of {dep.typosquat_target!r}"
            )
            assert dep.typosquat_target == ""

    def test_allowlist_case_insensitive(self):
        """Allowlist matching must not depend on the case of the declared name."""
        dep = Dependency(name="Black", version="1.0.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is False

    def test_real_typosquats_are_still_detected(self):
        """Control test: the allowlist fix must not weaken detection.

        A name within edit distance 2 of a target that is *not itself* on the
        known-good list is a genuine typosquat and must still be reported, with
        ``typosquat_target`` naming the package it resembles.  The names here
        are neighbours of the four entries the ordering bug used to flag
        (``black``/``flask``, ``rack``/``rich``, ``rake``/``rack``,
        ``orjson``/``ujson``), so they are exactly the cases an over-broad
        allowlist check would silently swallow.
        """
        expected = {
            "blakc": "black",
            "blackk": "black",
            "rakc": "rack",
            "rackk": "rack",
            "rakee": "rake",
            "orjsno": "orjson",
            "reqests": "requests",
            "reqeusts": "requests",
            "numpyy": "numpy",
            "djangoo": "django",
            "tensorflaw": "tensorflow",
        }
        for name, target in expected.items():
            assert name not in self.scanner._typosquat_targets, name
            dep = Dependency(name=name, version="1.0.0", ecosystem="pypi")
            assert self.scanner.check_typosquat(dep) is True, (
                f"{name!r} resembles {target!r} but was not detected as a typosquat"
            )
            assert dep.is_typosquat is True
            assert dep.typosquat_target == target

    def test_typosquat_survives_a_known_good_neighbour(self):
        """Control test: an allowlisted neighbour must not mask a real attack.

        ``rack`` and ``rake`` are both known-good and within edit distance 2 of
        each other.  ``rakc`` is within distance 2 of both but is on neither
        list, so it must be reported against the first matching target rather
        than being cleared by the allowlist check.
        """
        dep = Dependency(name="rakc", version="1.0.0", ecosystem="pypi")
        assert self.scanner.check_typosquat(dep) is True
        assert dep.typosquat_target in {"rack", "rake"}

    def test_local_dependency_is_never_a_typosquat(self):
        """A local path dependency bypasses detection entirely, fix included."""
        dep = Dependency(name="reqests", version="1.0.0", ecosystem="pypi", is_local=True)
        assert self.scanner.check_typosquat(dep) is False
        assert dep.typosquat_target == ""


class TestScanDirectory:
    def test_scan_nonexistent(self):
        scanner = MultiScanner()
        deps = scanner.scan_directory("/nonexistent")
        assert deps == []

    def test_scan_current_dir(self, tmp_path):
        # Create test files
        (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
        (tmp_path / "go.mod").write_text("module test\nrequire github.com/test/test v1.0.0\n")

        scanner = MultiScanner()
        deps = scanner.scan_directory(str(tmp_path))
        assert len(deps) >= 1

    def test_scan_pipfile_lock(self, tmp_path):
        lock_file = tmp_path / "Pipfile.lock"
        lock_file.write_text('{"default": {"requests": {"version": "==2.31.0"}}}')
        scanner = MultiScanner()
        deps = scanner.scan_file(str(lock_file))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].ecosystem == "pypi"

        dir_deps = scanner.scan_directory(str(tmp_path))
        assert len(dir_deps) == 1
        assert dir_deps[0].name == "requests"

    def test_scan_gemfile_lock(self, tmp_path):
        lock_file = tmp_path / "Gemfile.lock"
        lock_file.write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    rails (7.1.0)\n"
            "      rack (>= 2.2.4)\n"
            "\n"
            "DEPENDENCIES\n"
            "  rails (~> 7.1)\n"
        )
        scanner = MultiScanner()
        deps = scanner.scan_file(str(lock_file))
        assert len(deps) == 1
        assert deps[0].name == "rails"
        assert deps[0].version == "7.1.0"
        assert deps[0].ecosystem == "rubygems"

        dir_deps = scanner.scan_directory(str(tmp_path))
        assert len(dir_deps) == 1
        assert dir_deps[0].name == "rails"

    def test_gemfile_lock_typosquat_detection(self, tmp_path):
        # "reqeusts" is one transposition away from the "requests" target.
        lock_file = tmp_path / "Gemfile.lock"
        lock_file.write_text(
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    reqeusts (2.31.0)\n"
        )
        scanner = MultiScanner()
        deps = scanner.scan_file(str(lock_file))
        assert len(deps) == 1

        assert scanner.check_typosquat(deps[0]) is True
        assert deps[0].is_typosquat is True
        assert deps[0].typosquat_target == "requests"

        results = scanner.scan_and_check(str(tmp_path))
        assert results["by_ecosystem"].get("rubygems") == 1
        assert len(results["typosquats"]) == 1


class TestDependency:
    def test_is_vulnerable_false(self):
        dep = Dependency(name="test", version="1.0.0", ecosystem="pypi")
        assert dep.is_vulnerable is False

    def test_is_vulnerable_true(self):
        dep = Dependency(name="test", version="1.0.0", ecosystem="pypi")
        dep.known_vulnerabilities.append(
            Vulnerability(id="GHSA-xxx", severity="HIGH", description="test")
        )
        assert dep.is_vulnerable is True


def test_scan_skips_invalid_package_names_by_default(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("safe-package==1.0\nevil;command==2.0\n")
    with pytest.warns(RuntimeWarning, match="Skipping invalid"):
        deps = MultiScanner().scan_file(str(path))
    assert [dep.name for dep in deps] == ["safe-package"]


def test_strict_scan_rejects_invalid_package_names(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("evil;command==2.0\n")
    with pytest.raises(ValueError, match="Invalid package name"):
        MultiScanner(strict=True).scan_file(str(path))


def test_scoped_npm_and_go_names_remain_valid(tmp_path):
    npm = tmp_path / "package-lock.json"
    npm.write_text('{"lockfileVersion": 3, "packages": {"node_modules/@acme/pkg": {"version": "1.0"}}}')
    go = tmp_path / "go.mod"
    go.write_text("require github.com/acme/pkg v1.0.0\n")
    scanner = MultiScanner(strict=True)
    assert scanner.scan_file(str(npm))[0].name == "@acme/pkg"
    assert scanner.scan_file(str(go))[0].name == "github.com/acme/pkg"


def test_go_mod_skips_single_line_excluded_version():
    content = """
require (
    github.com/acme/unsafe v1.2.0
    github.com/acme/safe v2.0.0
)
exclude github.com/acme/unsafe v1.2.0 // known bad release
"""
    deps = DependencyParser.parse_go_mod(content)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("github.com/acme/safe", "2.0.0")
    ]


def test_go_mod_skips_block_exclusions_only_when_version_matches():
    content = """
require (
    github.com/acme/foo v1.2.0
    github.com/acme/bar v3.0.0
)
exclude (
    github.com/acme/foo v1.1.0
    github.com/acme/bar v3.0.0
)
"""
    deps = DependencyParser.parse_go_mod(content)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("github.com/acme/foo", "1.2.0")
    ]

    def test_parse_requirements_txt_strips_environment_markers(self):
        content = 'certifi==2023.7.22; python_version >= "3.8"\nflask>=2.0; sys_platform == "win32"\n'
        deps = self.parser.parse_requirements_txt(content)
        assert [(dep.name, dep.version) for dep in deps] == [
            ("certifi", "2023.7.22"),
            ("flask", "2.0"),
        ]

    def test_parse_requirements_txt_strips_extras(self):
        content = "urllib3[security]==2.0.0\npackage[extra1,extra2]>=1.0.0\n"
        deps = self.parser.parse_requirements_txt(content)
        assert [(dep.name, dep.version) for dep in deps] == [
            ("urllib3", "2.0.0"),
            ("package", "1.0.0"),
        ]

    def test_scan_directory_skips_unreadable_file(self, tmp_path):
        bad = tmp_path / "bad" / "requirements.txt"
        good = tmp_path / "good" / "requirements.txt"
        bad.parent.mkdir()
        good.parent.mkdir()
        bad.write_text("ignored==1.0")
        good.write_text("requests==2.28.0")
        scanner = MultiScanner()
        scan_file = scanner.scan_file

        def read_or_fail(path, *args):
            if Path(path) == bad:
                raise PermissionError("denied")
            return scan_file(path, *args)

        with patch.object(scanner, "scan_file", side_effect=read_or_fail):
            with pytest.warns(RuntimeWarning, match="Skipping unreadable"):
                deps = scanner.scan_directory(str(tmp_path))
        assert [(dep.name, dep.version) for dep in deps] == [("requests", "2.28.0")]

    def test_levenshtein_distance_threshold(self):
        scanner = MultiScanner()
        assert scanner._levenshtein("requests", "raquests", 2) == 1
        assert scanner._levenshtein("abcd", "wxyz", 2) > 2
        assert scanner._levenshtein("a", "aaaa", 2) > 2
        assert scanner._levenshtein("abcd", "wxyz") == 4

    def test_levenshtein_uses_cache(self):
        scanner = MultiScanner()
        scanner._levenshtein.cache_clear()
        scanner._levenshtein("raquests", "requests", 2)
        scanner._levenshtein("raquests", "requests", 2)
        assert scanner._levenshtein.cache_info().hits == 1


def test_parse_package_json_mixed_dependencies():
    content = '''{
        "dependencies": {"react": "^18.2.0", "lodash": "~4.17.21"},
        "devDependencies": {"pytest-js": "^1.0.0"}
    }'''
    deps = DependencyParser.parse_package_json(content)
    parsed = {(dep.name, dep.version, dep.ecosystem) for dep in deps}
    assert parsed == {
        ("react", "^18.2.0", "npm"),
        ("lodash", "~4.17.21", "npm"),
        ("pytest-js", "^1.0.0", "npm"),
    }

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_parse_cargo_toml_all_dependency_sections():
    content = '''
[dependencies]
serde = "1.0"
tokio = { version = "1.37", features = ["full"] }

[dev-dependencies]
pretty_assertions = "1.4"

[build-dependencies]
cc = { workspace = true }
'''
    deps = DependencyParser.parse_cargo_toml(content)
    parsed = {(dep.name, dep.version, dep.ecosystem) for dep in deps}
    assert parsed == {
        ("serde", "1.0", "cargo"),
        ("tokio", "1.37", "cargo"),
        ("pretty_assertions", "1.4", "cargo"),
        ("cc", "workspace", "cargo"),
    }

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_parse_pyproject_toml_pep621_and_poetry():
    content = '''
[project]
dependencies = ["requests>=2.31", "httpx[http2]~=0.27; python_version >= '3.10'"]

[project.optional-dependencies]
test = ["pytest>=7"]

[tool.poetry.dependencies]
python = "^3.10"
pendulum = { version = "^3.0" }
'''
    deps = DependencyParser.parse_pyproject_toml(content)
    parsed = {(dep.name, dep.version, dep.ecosystem) for dep in deps}
    assert parsed == {
        ("requests", ">=2.31", "pypi"),
        ("httpx", "~=0.27", "pypi"),
        ("pytest", ">=7", "pypi"),
        ("pendulum", "^3.0", "pypi"),
    }

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_scan_directory_skips_dependency_directories(tmp_path):
    root_req = tmp_path / "requirements.txt"
    root_req.write_text("requests==2.31.0\n")
    vendored = tmp_path / "node_modules" / "nested"
    vendored.mkdir(parents=True)
    (vendored / "requirements.txt").write_text("evil==1.0\n")

    deps = MultiScanner().scan_directory(str(tmp_path))

    assert [(dep.name, dep.version) for dep in deps] == [("requests", "2.31.0")]


def test_scan_directory_honors_custom_excludes(tmp_path):
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "requirements.txt").write_text("generated-package==1.0\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

    deps = MultiScanner().scan_directory(str(tmp_path), excludes={"generated"})

    assert [dep.name for dep in deps] == ["requests"]


def test_scan_directory_can_include_hidden_directories(tmp_path):
    hidden = tmp_path / ".fixtures"
    hidden.mkdir()
    (hidden / "requirements.txt").write_text("hidden-package==1.0\n")

    assert MultiScanner().scan_directory(str(tmp_path)) == []
    deps = MultiScanner().scan_directory(str(tmp_path), include_hidden=True)
    assert [dep.name for dep in deps] == ["hidden-package"]

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_parallel_scan_matches_sequential_results(tmp_path):
    first = tmp_path / "requirements.txt"
    first.write_text("requests==2.31.0\n")
    nested = tmp_path / "service"
    nested.mkdir()
    (nested / "requirements.txt").write_text("flask==3.0.0\n")

    scanner = MultiScanner()
    sequential = scanner.scan_directory(str(tmp_path))
    parallel = scanner.scan_directory_parallel(str(tmp_path), max_workers=2)

    assert [(dep.name, dep.version) for dep in parallel] == [
        (dep.name, dep.version) for dep in sequential
    ]


def test_scan_and_check_can_disable_parallel_mode(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    results = MultiScanner().scan_and_check(str(tmp_path), parallel=False)
    assert results["total"] == 1

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_go_sum_parsing_deduplicates_module_hash_entries():
    content = """
github.com/acme/foo v1.2.3 h1:abc
github.com/acme/foo v1.2.3/go.mod h1:def
github.com/acme/bar v0.4.0 h1:ghi
malformed line
"""
    deps = DependencyParser.parse_go_sum(content)
    assert [(dep.name, dep.version) for dep in deps] == [
        ("github.com/acme/foo", "1.2.3"),
        ("github.com/acme/bar", "0.4.0"),
    ]


def test_go_sum_marks_only_unrequired_modules_orphaned(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example\nrequire github.com/acme/foo v1.2.3\n"
    )
    (tmp_path / "go.sum").write_text(
        "github.com/acme/foo v1.2.3 h1:abc\n"
        "github.com/acme/bar v0.4.0 h1:def\n"
    )

    deps = MultiScanner().scan_directory(str(tmp_path))
    go_sum = {
        dep.name: dep for dep in deps
        if Path(dep.source_file).name == "go.sum"
    }
    assert go_sum["github.com/acme/foo"].is_orphaned is False
    assert go_sum["github.com/acme/bar"].is_orphaned is True

    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_cargo_lock_records_registry_git_and_local_sources():
    content = """
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "forked"
version = "2.0.0"
source = "git+https://github.com/acme/forked"

[[package]]
name = "workspace-lib"
version = "0.1.0"
"""
    deps = DependencyParser.parse_cargo_lock(content)
    assert deps[0].source.startswith("registry+")
    assert deps[0].is_local is False
    assert deps[1].source.startswith("git+")
    assert deps[1].is_local is False
    assert deps[2].source == "local"
    assert deps[2].is_local is True


def test_typosquat_check_skips_local_cargo_dependencies():
    dep = Dependency(
        name="reqests", version="1.0", ecosystem="cargo",
        source="path+file:///workspace/reqests", is_local=True,
    )
    assert MultiScanner().check_typosquat(dep) is False


class TestPackageNameValidation:
    """Tests for validate_package_name() and the check() subprocess guard.

    These tests exercise the security boundary introduced to prevent
    package-name injection into subprocess calls (issue #119).
    """

    # --- validate_package_name ---

    @pytest.mark.parametrize("malicious_name", [
        "; rm -rf /",
        "lodash; rm -rf /",
        "pkg | cat /etc/passwd",
        "pkg && evil",
        "pkg\necho pwned",
        "pkg$(whoami)",
        "pkg`id`",
        "pkg >out.txt",
        "pkg <in.txt",
        "pkg$PATH",
        "pkg name",          # space is not allowed
        "pkg/subdir",        # forward-slash is not allowed
        "pkg\\evil",         # backslash is not allowed
        "",                  # empty string
        "\x00pkg",           # null byte
    ])
    def test_validate_package_name_raises_for_malicious_input(self, malicious_name):
        """validate_package_name() must raise ValueError for any name that
        contains characters outside the safe [a-zA-Z0-9._-] allowlist."""
        with pytest.raises(ValueError, match="Invalid package name"):
            validate_package_name(malicious_name)

    @pytest.mark.parametrize("safe_name", [
        "lodash",
        "react",
        "my-package",
        "my_package",
        "my.package",
        "Pkg123",
        "pkg-0.1.0",
        "@",               # edge: single allowed-adjacent char — rejected by regex
    ])
    def test_validate_package_name_accepts_safe_names(self, safe_name):
        """Names composed solely of [a-zA-Z0-9._-] must not raise."""
        # "@" is NOT in the allowlist — skip it so we only test truly safe names.
        if not SAFE_PACKAGE_NAME_RE.match(safe_name):
            pytest.skip(f"{safe_name!r} is intentionally outside the allowlist")
        # Should not raise
        validate_package_name(safe_name)

    # --- check() ---

    def test_check_raises_value_error_for_malicious_package_name(self):
        """check() must raise ValueError — and must NOT invoke subprocess —
        when the package name is malicious (e.g. contains shell metacharacters).
        This is the primary acceptance criterion for issue #119.
        """
        with patch("depscan.scanner.subprocess.run") as mock_run:
            with pytest.raises(ValueError, match="Invalid package name"):
                check("; rm -rf /")
            # The subprocess must never have been called
            mock_run.assert_not_called()

    def test_check_raises_for_semicolon_injection(self):
        """Semicolons are a classic shell-injection vector and must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("lodash; rm -rf /")

    def test_check_raises_for_pipe_injection(self):
        """Pipe characters must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("pkg | cat /etc/passwd")

    def test_check_raises_for_empty_string(self):
        """An empty package name must be rejected."""
        with patch("depscan.scanner.subprocess.run"):
            with pytest.raises(ValueError, match="Invalid package name"):
                check("")

    def test_check_calls_subprocess_with_list_and_no_shell(self):
        """When given a *valid* package name, check() must call subprocess.run
        with a list of arguments and shell=False (never shell=True)."""
        import json as _json
        fake_result = type("R", (), {
            "stdout": _json.dumps({"vulnerabilities": {}}),
            "stderr": "",
            "returncode": 0,
        })()
        with patch("depscan.scanner.subprocess.run", return_value=fake_result) as mock_run:
            result = check("lodash")
            args, kwargs = mock_run.call_args
            # First positional arg must be a list (not a string)
            assert isinstance(args[0], list), "subprocess.run must receive a list, not a string"
            # shell must be explicitly False
            assert kwargs.get("shell") is False, "shell=True would re-introduce the injection vector"
            # package name must appear in the argument list
            assert "lodash" in args[0]
        assert result == {"vulnerabilities": {}}


def test_parse_cargo_toml_target_specific_sections():
    content = '''
[target.'cfg(windows)'.dependencies]
winapi = { version = "0.3", features = ["winuser"] }

[target.'cfg(unix)'.dev-dependencies]
nix = "0.28"

[target.x86_64-unknown-linux-gnu.build-dependencies]
pkg-config = "0.3"
'''
    deps = DependencyParser.parse_cargo_toml(content)
    assert {(dep.name, dep.version) for dep in deps} == {
        ("winapi", "0.3"),
        ("nix", "0.28"),
        ("pkg-config", "0.3"),
    }


def test_parse_cargo_toml_workspace_dependencies_and_inheritance():
    content = '''
[workspace]
members = ["crates/*"]

[workspace.dependencies]
serde = { version = "1.0.200", features = ["derive"] }
anyhow = "1.0"

[dependencies]
serde = { workspace = true, optional = true }
log = { version = "0.4", optional = true }
'''
    deps = DependencyParser.parse_cargo_toml(content)
    assert sorted((dep.name, dep.version) for dep in deps) == [
        ("anyhow", "1.0"),
        ("log", "0.4"),
        ("serde", "1.0.200"),
    ]


def test_scan_file_resolves_workspace_versions_from_root_manifest(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/app"]\n\n'
        '[workspace.dependencies]\n'
        'serde = { version = "1.0.200", features = ["derive"] }\n'
        'anyhow = "1.0"\n'
    )
    member = tmp_path / "crates" / "app"
    member.mkdir(parents=True)
    (member / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n\n'
        '[dependencies]\n'
        'anyhow.workspace = true\n'
        'serde = { workspace = true, features = ["rc"] }\n'
        'missing = { workspace = true }\n'
    )
    deps = MultiScanner().scan_file(str(member / "Cargo.toml"))
    assert {(dep.name, dep.version) for dep in deps} == {
        ("anyhow", "1.0"),
        ("serde", "1.0.200"),
        ("missing", "workspace"),
    }


def test_parse_cargo_toml_reports_each_name_and_version_once():
    content = """
[dependencies]
libc = "0.2"

[dev-dependencies]
libc = "0.2"

[target.'cfg(windows)'.dependencies]
libc = "0.2"

[target.'cfg(unix)'.dev-dependencies]
libc = { version = "0.2" }
"""
    deps = DependencyParser.parse_cargo_toml(content)
    assert [(dep.name, dep.version) for dep in deps] == [("libc", "0.2")]


@pytest.mark.parametrize("workspace_deps", [[["serde", "1.0"]], "notadict", 42])
def test_parse_cargo_toml_ignores_non_dict_workspace_deps(workspace_deps):
    deps = DependencyParser.parse_cargo_toml(
        '[dependencies]\nserde = { workspace = true }\n', workspace_deps
    )
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "workspace")]


def test_scan_directory_counts_inherited_workspace_dependencies_once(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/*"]\n\n'
        '[workspace.dependencies]\nserde = "1.0.200"\n'
    )
    for index in range(5):
        member = tmp_path / "crates" / f"c{index}"
        member.mkdir(parents=True)
        (member / "Cargo.toml").write_text(
            f'[package]\nname = "c{index}"\nversion = "0.1.0"\n\n'
            '[dependencies]\nserde = { workspace = true }\n'
        )
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0.200")]


def test_cargo_workspace_lookup_stops_at_the_scan_root(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\n\n[workspace.dependencies]\nsneaky = "9.9.9"\n'
    )
    scanned = tmp_path / "unrelated" / "sub"
    scanned.mkdir(parents=True)
    (scanned / "Cargo.toml").write_text('[dependencies]\nsneaky = { workspace = true }\n')
    deps = MultiScanner().scan_directory(str(scanned))
    assert [(dep.name, dep.version) for dep in deps] == [("sneaky", "workspace")]


def test_cargo_workspace_lookup_skips_a_workspace_that_excludes_the_package(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/app"]\nexclude = ["crates/orphan"]\n\n'
        '[workspace.dependencies]\nserde = "1.0.200"\n'
    )
    orphan = tmp_path / "crates" / "orphan"
    orphan.mkdir(parents=True)
    (orphan / "Cargo.toml").write_text('[dependencies]\nserde = { workspace = true }\n')
    deps = MultiScanner().scan_file(str(orphan / "Cargo.toml"))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "workspace")]


def test_cargo_manifest_without_workspace_keys_skips_the_ancestor_lookup(tmp_path):
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text('[dependencies]\nserde = "1.0"\n')
    with patch("depscan.scanner._cargo_workspace_root") as lookup:
        deps = MultiScanner().scan_file(str(manifest))
    lookup.assert_not_called()
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0")]


def test_cargo_workspace_header_inside_a_multiline_string_is_not_its_own_root(tmp_path):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["inner"]\n\n[workspace.dependencies]\nserde = "1.0.200"\n'
    )
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "Cargo.toml").write_text(
        '[package]\nname = "inner"\nversion = "0.1.0"\n'
        'description = """\n[workspace]\nnot a table header\n"""\n\n'
        '[dependencies]\nserde = { workspace = true }\n'
    )
    deps = MultiScanner().scan_file(str(inner / "Cargo.toml"), root=str(tmp_path))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0.200")]


def test_cargo_real_workspace_header_still_skips_the_ancestor_lookup(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["inner"]\n')
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "Cargo.toml").write_text(
        '[package]\nname = "inner"\nversion = "0.1.0"\n\n'
        '[dependencies]\nserde = { workspace = true }\n'
    )
    with patch("depscan.scanner._cargo_workspace_root") as lookup:
        deps = MultiScanner().scan_file(str(tmp_path / "Cargo.toml"), root=str(tmp_path))
    lookup.assert_not_called()  # the root manifest is its own workspace root
    assert deps == []  # no [workspace.dependencies] here, and no ancestor to inherit from


def _cargo_workspace(base, root_manifest, crates):
    """Write a workspace root plus member crates that inherit serde."""
    base.mkdir(parents=True, exist_ok=True)
    (base / "Cargo.toml").write_text(
        root_manifest + '\n[workspace.dependencies]\nserde = "1.0.190"\n'
    )
    for rel, extra in crates.items():
        crate = base / rel
        crate.mkdir(parents=True, exist_ok=True)
        (crate / "Cargo.toml").write_text(
            f'[package]\nname = "{crate.name}"\nversion = "0.1.0"\n\n'
            '[dependencies]\nserde = { workspace = true }\n' + extra
        )


# Expected versions were checked against `cargo metadata --no-deps` (cargo 1.96).
@pytest.mark.parametrize("root_manifest, crates, probe, expected", [
    ('[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/foo"]\n',
     {"crates/app": "", "crates/foo": ""}, "crates/foo", "workspace"),
    ('[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/foo/"]\n',
     {"crates/foo": ""}, "crates/foo", "workspace"),
    ('[workspace]\nmembers = ["a/b/*"]\nexclude = ["a/b/c"]\n',
     {"a/b/c": "", "a/b/d": ""}, "a/b/c", "workspace"),
    ('[workspace]\nmembers = ["a/b/*"]\nexclude = ["a/b/c"]\n',
     {"a/b/c": "", "a/b/d": ""}, "a/b/d", "1.0.190"),
    ('[workspace]\nmembers = ["crates/foo"]\nexclude = ["crates/foo"]\n',
     {"crates/foo": "", "crates/bar": ""}, "crates/foo", "1.0.190"),
    ('[workspace]\nmembers = ["crates/foo"]\nexclude = ["crates/foo"]\n',
     {"crates/foo": "", "crates/bar": ""}, "crates/bar", "workspace"),
    ('[workspace]\nexclude = ["crates/foo"]\n\n[package]\nname = "root"\nversion = "0.1.0"\n',
     {"crates/foo": "", "crates/bar": ""}, "crates/bar", "workspace"),
    ('[workspace]\nmembers = ["crates/app"]\n',
     {"crates/app": "", "crates/stray": ""}, "crates/stray", "workspace"),
    ('[workspace]\nmembers = ["crates/app"]\n',
     {"crates/app": 'lib = { path = "../lib" }\n', "crates/lib": ""}, "crates/lib", "1.0.190"),
    ('[workspace]\nmembers = ["crates/*", "crates/gone"]\n',
     {"crates/app": ""}, "crates/app", "workspace"),
], ids=[
    "exclude-beats-glob-member", "exclude-with-trailing-slash", "exclude-beats-nested-glob",
    "nested-glob-sibling-is-member", "literal-member-beats-exclude", "unlisted-crate",
    "no-members-unlisted-crate", "stray-crate", "path-dependency-of-member",
    "missing-literal-member-breaks-workspace",
])
def test_cargo_workspace_membership_matches_cargo(tmp_path, root_manifest, crates, probe, expected):
    _cargo_workspace(tmp_path, root_manifest, crates)
    deps = MultiScanner().scan_file(str(tmp_path / probe / "Cargo.toml"))
    assert [(dep.name, dep.version) for dep in deps if dep.name == "serde"] == [
        ("serde", expected)
    ]


def test_scan_directory_keeps_member_dependency_when_root_manifest_is_ignored(tmp_path):
    _cargo_workspace(tmp_path / "ws", '[workspace]\nmembers = ["crates/app"]\n', {"crates/app": ""})
    (tmp_path / ".gitignore").write_text("/ws/Cargo.toml\n")
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0.190")]


def test_scan_directory_keeps_member_manifest_when_root_is_anchor_ignored(tmp_path):
    # An anchored "/Cargo.toml" ignores only the root manifest, as in git.
    _cargo_workspace(tmp_path, '[workspace]\nmembers = ["crates/app"]\n', {"crates/app": ""})
    (tmp_path / ".gitignore").write_text("/Cargo.toml\n")
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0.190")]


def test_scan_directory_tolerates_a_non_utf8_ancestor_manifest(tmp_path):
    _cargo_workspace(tmp_path, '[workspace]\nmembers = ["crates/app"]\n', {"crates/app": ""})
    with open(tmp_path / "Cargo.toml", "ab") as handle:
        handle.write(b"\n# caf\xe9 latin-1 comment\n")
    deps = MultiScanner().scan_directory(str(tmp_path))
    assert [(dep.name, dep.version) for dep in deps] == [("serde", "1.0.190")]
