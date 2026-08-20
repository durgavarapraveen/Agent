"""
Autonomous Pentesting Agent - Entry Point

Single target:
  python main.py --target example.com
  python main.py --target example.com --auth auth.txt --tier SHALLOW

Multiple targets:
  python main.py --targets example.com,app2.io,api.service.com
  python main.py --targets-file targets.txt --tier POC
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from core.config import load_config
from core.central_brain import CentralBrain
from core.meta_brain import MetaBrain

_LOG_FMT = '[%(asctime)s] %(name)s - %(levelname)s - %(message)s'


class _TruncatingFormatter(logging.Formatter):
    """Console-only: keep the terminal readable by capping long messages.
    The file handler uses the plain formatter and records the FULL message."""

    def __init__(self, fmt=None, max_len=220):
        super().__init__(fmt)
        self.max_len = max_len

    def format(self, record):
        s = super().format(record)
        if len(s) > self.max_len:
            s = s[:self.max_len] + " …(full in pentest.log)"
        return s


_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(_TruncatingFormatter(_LOG_FMT))

_file = logging.FileHandler("pentest.log", encoding="utf-8")   # FULL, untruncated
_file.setFormatter(logging.Formatter(_LOG_FMT))

logging.basicConfig(level=logging.INFO, handlers=[_console, _file])
logger = logging.getLogger(__name__)


async def run_single(target: str, auth_file: str = None, tier: str = "POC"):
    """Single target pentest"""
    auth_document = ""
    if auth_file:
        auth_path = Path(auth_file)
        if auth_path.exists():
            auth_document = auth_path.read_text(encoding="utf-8")
        else:
            logger.error(f"Auth file not found: {auth_path}")
            sys.exit(1)

    scope = {"domains": [target], "max_tier": tier}
    brain = CentralBrain(target=target, scope=scope)
    await brain.run(auth_document=auth_document)


async def run_multi(targets: list, auth_file: str = None):
    """Multi-target parallel pentest"""
    auth_document = ""
    if auth_file:
        auth_path = Path(auth_file)
        if auth_path.exists():
            auth_document = auth_path.read_text(encoding="utf-8")

    meta = MetaBrain(targets, auth_document=auth_document)
    await meta.run_all()


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com
  python main.py --target example.com --auth auth.txt --tier SHALLOW
  python main.py --targets example.com,app2.io,api.com
  python main.py --targets-file targets.txt --tier POC
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Single target domain or URL")
    group.add_argument("--targets", help="Comma-separated list of targets")
    group.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--auth", default=None, help="Authorization document")
    parser.add_argument("--tier", default="POC",
                         choices=["POC", "SHALLOW", "DEEP"],
                         help="Max exploitation tier (default: POC)")
    args = parser.parse_args()

    # Load .env config
    config = load_config()

    # Override tier in config
    config.config["MAX_EXPLOITATION_TIER"] = args.tier

    logger.info("=" * 60)
    logger.info("AUTONOMOUS PENTESTING AGENT v2.0")
    logger.info("=" * 60)

    if args.target:
        # Single target
        logger.info(f"Mode: Single target")
        logger.info(f"Target: {args.target}")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        asyncio.run(run_single(args.target, args.auth, args.tier))

    elif args.targets:
        # Multi-target from CLI
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        logger.info(f"Mode: Multi-target ({len(targets)} targets)")
        for t in targets:
            logger.info(f"  - {t}")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        asyncio.run(run_multi(targets, args.auth))

    elif args.targets_file:
        # Multi-target from file
        path = Path(args.targets_file)
        if not path.exists():
            logger.error(f"Targets file not found: {path}")
            sys.exit(1)
        targets = [
            line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        logger.info(f"Mode: Multi-target ({len(targets)} from {path})")
        logger.info(f"Tier: {args.tier}")
        logger.info("=" * 60)
        asyncio.run(run_multi(targets, args.auth))


if __name__ == "__main__":
    main()