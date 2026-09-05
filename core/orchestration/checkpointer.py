import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class Checkpointer:
    """Handles saving and restoring the autonomous pentest state."""

    def __init__(self, checkpoints_dir: str = None):
        from core.common.reports_config import reports_enabled, reports_dir
        self._reports_enabled = reports_enabled()
        if checkpoints_dir is None:
            checkpoints_dir = str(reports_dir() / "checkpoints")
        self.checkpoints_dir = Path(checkpoints_dir)
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)

    def save_checkpoint(self, brain) -> str:
        """Saves current phase and SharedContext state to JSON. current_phase = the NEXT phase to run on resume."""
        # Opt-out: set CHECKPOINT_TO_FILE=false to skip file checkpoints (resume via
        # --resume depends on them, so leaving them on is recommended).
        if os.getenv("CHECKPOINT_TO_FILE", "true").lower() in ("false", "0", "no", "off"):
            return ""
        target_slug = brain.target.replace('://', '_').replace('/', '_').replace(':', '_')
        checkpoint_id = f"checkpoint_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = self.checkpoints_dir / f"{checkpoint_id}.json"

        try:
            ctx = brain.ctx
            state = {
                "checkpoint_id": checkpoint_id,
                "timestamp": datetime.now().isoformat(),
                "target": brain.target,
                "current_phase": brain.current_phase.value if brain.current_phase else None,
                "phase_history": [ph.phase_name if hasattr(ph, 'phase_name') else str(ph) for ph in getattr(brain, 'phase_history', [])],
                "shared_context": {
                    "subdomains": getattr(ctx, 'subdomains', []),
                    "ips": getattr(ctx, 'ips', []),
                    "ports": getattr(ctx, 'ports', []),
                    "technologies": getattr(ctx, 'technologies', {}),
                    "endpoints": getattr(ctx, 'endpoints', {}),
                    "directories": getattr(ctx, 'directories', []),
                    "headers": getattr(ctx, 'headers', {}),
                    "js_files": getattr(ctx, 'js_files', []),
                    "secrets": getattr(ctx, 'secrets', []),
                    "ssl_info": getattr(ctx, 'ssl_info', {}),
                    "vulnerabilities": getattr(ctx, 'vulnerabilities', []),
                    "attack_chains": getattr(ctx, 'attack_chains', []),
                    "exploit_results": getattr(ctx, 'exploit_results', []),
                    "agents_spawned": getattr(ctx, 'agents_spawned', []),
                    "captured_requests": getattr(ctx, 'captured_requests', []),
                    "harvested_creds": getattr(ctx, 'harvested_creds', []),
                    "crawled_pages": getattr(ctx, 'crawled_pages', []),
                }
            }

            # Save site_profile and target_profile if they exist on ctx
            site_profile = getattr(ctx, '_store', {}).get('site_profile') if hasattr(ctx, '_store') else None
            if site_profile:
                state["shared_context"]["site_profile"] = site_profile
            target_profile = getattr(ctx, '_store', {}).get('target_profile') if hasattr(ctx, '_store') else None
            if target_profile:
                state["shared_context"]["target_profile"] = target_profile

            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2, default=str)

            # Write a latest-pointer for easy resume
            latest_path = self.checkpoints_dir / f"latest_{target_slug}.json"
            with open(latest_path, 'w') as f:
                json.dump({"path": str(filepath), "timestamp": state["timestamp"]}, f)

            logger.info(f"Checkpoint saved: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            return ""

    def get_latest_checkpoint(self, target: str) -> Optional[str]:
        """Returns the filepath of the latest checkpoint for a given target, or None."""
        target_slug = target.replace('://', '_').replace('/', '_').replace(':', '_')
        latest_path = self.checkpoints_dir / f"latest_{target_slug}.json"
        if not latest_path.exists():
            return None
        try:
            with open(latest_path, 'r') as f:
                data = json.load(f)
            cp_path = data.get("path")
            if cp_path and Path(cp_path).exists():
                return cp_path
        except Exception:
            pass
        return None

    def load_checkpoint(self, filepath: str) -> Dict:
        """Loads a checkpoint JSON dictionary from a file."""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            logger.info(f"Checkpoint loaded: {filepath}")
            return state
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return {}

    def apply_checkpoint(self, brain, state: Dict):
        """Rehydrates a CentralBrain instance with a loaded state dictionary."""
        try:
            phase_val = state.get("current_phase")
            if phase_val:
                try:
                    from core.orchestration.central_brain import ExecutionPhase
                    brain.current_phase = ExecutionPhase(phase_val)
                    logger.info(f"Restored phase: {brain.current_phase.value}")
                except ValueError:
                    logger.warning(f"Unknown phase in checkpoint: {phase_val}")

            ctx_state = state.get("shared_context", {})

            restore_fields = [
                "subdomains", "ips", "ports", "technologies", "endpoints",
                "directories", "headers", "js_files", "secrets", "ssl_info",
                "vulnerabilities", "attack_chains", "exploit_results",
                "agents_spawned", "captured_requests", "harvested_creds", "crawled_pages",
            ]
            for field in restore_fields:
                if field in ctx_state:
                    setattr(brain.ctx, field, ctx_state[field])

            # Restore site_profile and target_profile to ctx store
            if "site_profile" in ctx_state and hasattr(brain.ctx, 'update'):
                brain.ctx.update('site_profile', ctx_state["site_profile"])
            if "target_profile" in ctx_state and hasattr(brain.ctx, 'update'):
                brain.ctx.update('target_profile', ctx_state["target_profile"])

            logger.info("Checkpoint state applied to brain context.")

        except Exception as e:
            logger.error(f"Failed to apply checkpoint state: {e}")
