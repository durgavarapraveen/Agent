"""
Smart Wordlist Selector — HexStrike-Style Context-Aware Dictionaries.

Maintains and dynamically generates technology-tailored wordlists for
directory bruteforcing, API endpoint discovery, and secret finding.

Inspired by HexStrike AI's dynamic wordlist selection.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional
from core.intelligence.target_profiler import TargetProfile

logger = logging.getLogger(__name__)

# Built-in curated wordlist definitions by technology/scenario
WORDLIST_TEMPLATES: Dict[str, List[str]] = {
    "nodejs_express": [
        "api", "api/v1", "api/v2", "api/v3", "routes", "rest", "rest/user", "rest/admin",
        "rest/products", "rest/user", "auth", "login", "signup", "register", "logout",
        "package.json", "package-lock.json", ".env", ".env.local", ".env.production",
        "npm-debug.log", "yarn.lock", "server.js", "app.js", "index.js", "config",
        "config/default.json", "config/production.json", "swagger.json", "api-docs",
        "metrics", "health", "healthz", "status", "debug", "console", "graphql", "graphiql"
    ],
    "wordpress": [
        "wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak", "wp-config.php~",
        "wp-content", "wp-content/plugins", "wp-content/themes", "wp-content/uploads",
        "wp-includes", "wp-json", "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
        "xmlrpc.php", "readme.html", "license.txt", "wp-cron.php", "wp-links-opml.php",
        "wp-mail.php", "wp-settings.php", "wp-signup.php", "wp-trackback.php", "author-sitemap.xml"
    ],
    "php": [
        "phpinfo.php", "info.php", "test.php", "config.php", "config.inc.php", "config.php.bak",
        "admin.php", "login.php", "dashboard.php", "install.php", "setup.php", "db.php",
        "database.php", "connect.php", "connection.php", "functions.php", "header.php",
        "footer.php", ".htaccess", ".htpasswd", "composer.json", "composer.lock", "vendor"
    ],
    "java_spring": [
        "actuator", "actuator/health", "actuator/env", "actuator/heapdump", "actuator/threaddump",
        "actuator/beans", "actuator/configprops", "actuator/mappings", "actuator/metrics",
        "actuator/loggers", "actuator/auditevents", "actuator/httptrace", "swagger-ui.html",
        "swagger-ui/index.html", "v2/api-docs", "v3/api-docs", "h2-console", "WEB-INF/web.xml",
        "META-INF/MANIFEST.MF", "application.properties", "application.yml"
    ],
    "dotnet_iis": [
        "web.config", "web.config.bak", "appsettings.json", "appsettings.Development.json",
        "elmah.axd", "trace.axd", "glimpse.axd", "aspnet_client", "bin", "bin/site.dll",
        "default.aspx", "login.aspx", "admin.aspx", "swagger/v1/swagger.json"
    ],
    "api_endpoints": [
        "api", "api/v1", "api/v2", "api/v3", "api/users", "api/auth", "api/login",
        "api/register", "api/admin", "api/config", "api/profile", "api/settings",
        "api/tokens", "api/keys", "api/upload", "api/download", "api/export",
        "api/search", "api/items", "api/data", "api/orders", "api/payments",
        "swagger.json", "openapi.json", "graphql", "graphiql", "altair", "playground"
    ],
    "cloud_secrets": [
        ".git/HEAD", ".git/config", ".git/index", ".gitignore", ".env", ".env.backup",
        ".aws/credentials", ".aws/config", ".gitlab-ci.yml", ".travis.yml", ".circleci/config.yml",
        "docker-compose.yml", "Dockerfile", "id_rsa", "id_rsa.pub", "id_dsa",
        "id_ecdsa", "id_ed25519", "backup.sql", "dump.sql", "database.sql", "db_backup.sql"
    ]
}


class SmartWordlistManager:
    """Selects and manages tailored wordlists based on target profiling."""

    _WORDLIST_DIR: Path = Path("data/wordlists")

    @classmethod
    def ensure_wordlists_exist(cls) -> None:
        """Create the data/wordlists directory and write template files if missing."""
        cls._WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
        for category, words in WORDLIST_TEMPLATES.items():
            filepath = cls._WORDLIST_DIR / f"wordlist_{category}.txt"
            if not filepath.exists():
                try:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write("\n".join(words) + "\n")
                    logger.info(f"SMART_WORDLIST_CREATED: {filepath} ({len(words)} entries)")
                except Exception as e:
                    logger.warning(f"Failed to create wordlist {filepath}: {e}")

    @classmethod
    def get_wordlist_for_profile(cls, profile: Optional[TargetProfile] = None) -> str:
        """Return the best tailored wordlist path for the given TargetProfile."""
        cls.ensure_wordlists_exist()

        if not profile:
            return cls.get_wordlist_path("api_endpoints")

        if profile.has_wordpress:
            return cls.get_wordlist_path("wordpress")
        elif profile.has_nodejs:
            return cls.get_wordlist_path("nodejs_express")
        elif profile.has_php:
            return cls.get_wordlist_path("php")
        elif profile.has_java:
            return cls.get_wordlist_path("java_spring")
        elif profile.has_dotnet:
            return cls.get_wordlist_path("dotnet_iis")
        elif profile.is_api:
            return cls.get_wordlist_path("api_endpoints")

        # Fallback to combined common wordlist
        return cls.get_wordlist_path("nodejs_express")

    @classmethod
    def get_wordlist_path(cls, category: str) -> str:
        """Get absolute path to a specific wordlist file."""
        cls.ensure_wordlists_exist()
        filepath = cls._WORDLIST_DIR / f"wordlist_{category}.txt"
        if filepath.exists():
            return str(filepath.resolve())
        return "/usr/share/wordlists/dirb/common.txt"

    @classmethod
    def get_combined_custom_wordlist(cls, profile: TargetProfile) -> str:
        """Build and return a combined custom wordlist merging tech words + secrets."""
        cls.ensure_wordlists_exist()
        combined: List[str] = []

        # Add base category
        if profile.has_wordpress:
            combined.extend(WORDLIST_TEMPLATES["wordpress"])
        if profile.has_nodejs:
            combined.extend(WORDLIST_TEMPLATES["nodejs_express"])
        if profile.has_php:
            combined.extend(WORDLIST_TEMPLATES["php"])
        if profile.has_java:
            combined.extend(WORDLIST_TEMPLATES["java_spring"])
        if profile.has_dotnet:
            combined.extend(WORDLIST_TEMPLATES["dotnet_iis"])

        # Always include API routes and secrets
        combined.extend(WORDLIST_TEMPLATES["api_endpoints"])
        combined.extend(WORDLIST_TEMPLATES["cloud_secrets"])

        # Deduplicate while preserving order
        seen = set()
        deduped = [w for w in combined if not (w in seen or seen.add(w))]

        out_path = cls._WORDLIST_DIR / "wordlist_combined_tailored.txt"
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(deduped) + "\n")
            return str(out_path.resolve())
        except Exception:
            return cls.get_wordlist_path("api_endpoints")
