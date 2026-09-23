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

    def test_parse_requirements_txt_strips_environment_markers(self):
        content = 'certifi==2023.7.22; python_version >= "3.8"\nflask>=2.0; sys_platform == "win32"\n'
        deps = self.parser.parse_requirements_txt(content)
        assert [(dep.name, dep.version) for dep in deps] == [
            ("certifi", "2023.7.22"),
            ("flask", "2.0"),
        ]

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
