"""depscan — Multi-ecosystem dependency scanner."""
from depscan.scanner import MultiScanner, DependencyParser, Dependency, Vulnerability
from depscan.sarif import to_sarif

__version__ = "0.1.0"

__all__ = ["MultiScanner", "DependencyParser", "Dependency", "Vulnerability", "to_sarif"]
