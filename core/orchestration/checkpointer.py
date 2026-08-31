import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)

class Checkpointer:
    """
    Handles saving and restoring the autonomous pentest state securely.
    Uses JSON serialization of essential SharedContext data.
    """
    
    def __init__(self, checkpoints_dir: str = "reports/checkpoints"):
        self.checkpoints_dir = Path(checkpoints_dir)
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        
    def save_checkpoint(self, brain) -> str:
        """Saves current Phase and SharedContext state to a JSON file."""
        checkpoint_id = f"checkpoint_{brain.target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filepath = self.checkpoints_dir / f"{checkpoint_id}.json"
        
        try:
            state = {
                "checkpoint_id": checkpoint_id,
                "timestamp": datetime.now().isoformat(),
                "target": brain.target,
                "current_phase": brain.current_phase.value if brain.current_phase else None,
                "shared_context": {
                    "subdomains": brain.ctx.subdomains,
                    "ips": brain.ctx.ips,
                    "ports": brain.ctx.ports,
                    "technologies": brain.ctx.technologies,
                    "endpoints": brain.ctx.endpoints,
                    "directories": brain.ctx.directories,
                    "headers": brain.ctx.headers,
                    "js_files": brain.ctx.js_files,
                    "secrets": brain.ctx.secrets,
                    "ssl_info": brain.ctx.ssl_info,
                    "vulnerabilities": brain.ctx.vulnerabilities,
                    "attack_chains": brain.ctx.attack_chains,
                    "exploit_results": brain.ctx.exploit_results,
                    "agents_spawned": brain.ctx.agents_spawned
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2, default=str)
                
            logger.info(f"Checkpoint saved successfully: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Failed to save checkpoint to {filepath}: {e}")
            return ""

    def load_checkpoint(self, filepath: str) -> Dict:
        """Loads a checkpoint JSON dictionary from a file."""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            logger.info(f"Checkpoint loaded successfully: {filepath}")
            return state
        except Exception as e:
            logger.error(f"Failed to load checkpoint from {filepath}: {e}")
            return {}

    def apply_checkpoint(self, brain, state: Dict):
        """Rehydrates a CentralBrain instance with a loaded state dictionary."""
        try:
            # Restore Current Phase
            phase_val = state.get("current_phase")
            if phase_val:
                try:
                    from core.orchestration.central_brain import ExecutionPhase
                    brain.current_phase = ExecutionPhase(phase_val)
                    logger.info(f"Restored phase: {brain.current_phase.value}")
                except ValueError:
                    logger.warning(f"Unknown phase in checkpoint: {phase_val}")
                    
            # Restore Shared Context
            ctx_state = state.get("shared_context", {})
            
            if "subdomains" in ctx_state:
                brain.ctx.subdomains = ctx_state["subdomains"]
            if "ips" in ctx_state:
                brain.ctx.ips = ctx_state["ips"]
            if "ports" in ctx_state:
                brain.ctx.ports = ctx_state["ports"]
            if "technologies" in ctx_state:
                brain.ctx.technologies = ctx_state["technologies"]
            if "endpoints" in ctx_state:
                brain.ctx.endpoints = ctx_state["endpoints"]
            if "directories" in ctx_state:
                brain.ctx.directories = ctx_state["directories"]
            if "headers" in ctx_state:
                brain.ctx.headers = ctx_state["headers"]
            if "js_files" in ctx_state:
                brain.ctx.js_files = ctx_state["js_files"]
            if "secrets" in ctx_state:
                brain.ctx.secrets = ctx_state["secrets"]
            if "ssl_info" in ctx_state:
                brain.ctx.ssl_info = ctx_state["ssl_info"]
            if "vulnerabilities" in ctx_state:
                brain.ctx.vulnerabilities = ctx_state["vulnerabilities"]
            if "attack_chains" in ctx_state:
                brain.ctx.attack_chains = ctx_state["attack_chains"]
            if "exploit_results" in ctx_state:
                brain.ctx.exploit_results = ctx_state["exploit_results"]
            if "agents_spawned" in ctx_state:
                brain.ctx.agents_spawned = ctx_state["agents_spawned"]
                
            logger.info("Successfully applied checkpoint state to brain context.")
            
        except Exception as e:
            logger.error(f"Failed to apply checkpoint state: {e}")
