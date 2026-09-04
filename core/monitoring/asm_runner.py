"""
Continuous ASM runner — repeatedly re-scans targets on an interval and prints
the delta each cycle. Snapshots/deltas are persisted under data/asm/<target>/.

Usage:
    python -m core.monitoring.asm_runner --target example.com --interval 3600
    python -m core.monitoring.asm_runner --target a.com --target b.com --cycles 3
    python -m core.monitoring.asm_runner --target example.com --once   # single cycle
"""

import argparse
import asyncio
import logging

from core.monitoring.asm_monitor import ASMMonitor

logger = logging.getLogger(__name__)


async def _run_cycle(target: str) -> None:
    # Imported lazily so a monitoring-only environment need not load the whole brain.
    from core.orchestration.central_brain import CentralBrain

    brain = CentralBrain(target)
    await brain.run_main_loop()
    delta = await ASMMonitor().record_and_diff(brain.ctx)
    print(ASMMonitor().render_delta_md(delta))


async def monitor(targets, interval: int, cycles: int) -> None:
    cycle = 0
    while cycles <= 0 or cycle < cycles:
        cycle += 1
        logger.info(f"[ASM] === cycle {cycle} ===")
        for t in targets:
            try:
                await _run_cycle(t)
            except Exception as e:
                logger.error(f"[ASM] cycle failed for {t}: {e}")
        if cycles > 0 and cycle >= cycles:
            break
        logger.info(f"[ASM] sleeping {interval}s until next cycle")
        await asyncio.sleep(interval)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser(prog="core.monitoring.asm_runner")
    p.add_argument("--target", action="append", required=True, help="target (repeatable)")
    p.add_argument("--interval", type=int, default=3600, help="seconds between cycles")
    p.add_argument("--cycles", type=int, default=0, help="number of cycles (0 = forever)")
    p.add_argument("--once", action="store_true", help="run a single cycle and exit")
    args = p.parse_args(argv)

    cycles = 1 if args.once else args.cycles
    asyncio.run(monitor(args.target, args.interval, cycles))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
