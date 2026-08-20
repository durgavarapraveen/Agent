"""
Claude Bridge Server - Local HTTP endpoint for Claude CLI
Routes prompts to claude CLI (using Max subscription authentication)
instead of paid API or local Ollama

Run: uvicorn claude_bridge_server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import logging
import uuid
import re
from typing import Dict, Optional
from datetime import datetime
from subprocess import Popen, PIPE, TimeoutExpired

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from uvicorn import run as uvicorn_run

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

CLAUDE_CLI_PATH = "claude"  # Assumes 'claude' is in PATH
EXECUTION_TIMEOUT = 300  # seconds (Sonnet needs ~3 min on Windows)
MAX_RETRIES = 2

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    prompt: str
    model: str = "haiku"  # haiku, sonnet, opus
    task_id: Optional[str] = None
    timeout: Optional[int] = EXECUTION_TIMEOUT

class StopRequest(BaseModel):
    task_id: str

class ChatResponse(BaseModel):
    task_id: str
    response: str
    tokens: Dict[str, int]
    model: str
    timestamp: str
    status: str = "success"

class ErrorResponse(BaseModel):
    task_id: str
    error: str
    status: str = "error"
    timestamp: str

# ═══════════════════════════════════════════════════════════════════════════
# PROCESS MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class ProcessManager:
    """Manages active Claude CLI subprocesses"""
    
    def __init__(self):
        self.processes: Dict[str, Dict] = {}
    
    def add_process(self, task_id: str, process: Popen):
        """Track a running process"""
        self.processes[task_id] = {
            "process": process,
            "started": datetime.now(),
            "model": None,
            "prompt": None
        }
        logger.info(f"[{task_id}] Process started (PID: {process.pid})")
    
    def get_process(self, task_id: str) -> Optional[Popen]:
        """Get running process by task_id"""
        if task_id in self.processes:
            return self.processes[task_id]["process"]
        return None
    
    def remove_process(self, task_id: str):
        """Clean up a process"""
        if task_id in self.processes:
            del self.processes[task_id]
            logger.info(f"[{task_id}] Process removed from tracking")
    
    def kill_process(self, task_id: str) -> bool:
        """Kill a running process"""
        process = self.get_process(task_id)
        if not process:
            return False
        
        try:
            process.kill()
            process.wait(timeout=5)
            logger.warning(f"[{task_id}] Process killed")
            self.remove_process(task_id)
            return True
        except Exception as e:
            logger.error(f"[{task_id}] Error killing process: {e}")
            return False
    
    def list_active(self) -> list:
        """List all active task IDs"""
        return list(self.processes.keys())

# ═══════════════════════════════════════════════════════════════════════════
# CLAUDE CLI EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════

class ClaudeExecutor:
    """Execute prompts via Claude CLI"""
    
    def __init__(self, process_manager: ProcessManager):
        self.pm = process_manager
    
    def _validate_model(self, model: str) -> str:
        """Validate model name"""
        valid_models = ["haiku", "sonnet", "opus"]
        if model.lower() not in valid_models:
            raise ValueError(f"Invalid model: {model}. Must be one of {valid_models}")
        return model.lower()
    
    def _build_command(self, prompt: str, model: str) -> list:
        """Build CLI command"""
        model = self._validate_model(model)
        
        # Claude CLI flags
        cmd = [
            CLAUDE_CLI_PATH,
            "-p", prompt,
            "--model", model,
            "--output-format", "json",
            "--dangerously-skip-permissions"
        ]
        
        return cmd
    
    def _parse_claude_output(self, stdout: str) -> tuple:
        """
        Parse Claude CLI JSON output
        
        Supports both formats:
        
        New format (Windows/recent):
        {
            "result": "...",
            "usage": {
                "input_tokens": 123,
                "output_tokens": 456,
                ...
            },
            ...
        }
        
        Old format:
        {
            "response": "...",
            "input_tokens": 123,
            "output_tokens": 456,
            "total_tokens": 579
        }
        """
        try:
            # Handle completely empty output
            if not stdout or not stdout.strip():
                logger.error("[ParseResult] ERROR - Claude CLI produced no output!")
                return "", {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            
            # Strip markdown code fences if Claude CLI wrapped response
            text = stdout.strip()
            if text.startswith("```"):
                lines = text.split('\n')
                lines = lines[1:]  # Skip opening ```
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]  # Remove closing ```
                text = '\n'.join(lines).strip()
                logger.info(f"[ParseResult] Stripped markdown code fences")
            
            # Check for empty after stripping
            if not text:
                logger.error("[ParseResult] ERROR - Output empty after stripping!")
                return "", {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            
            data = json.loads(text)
            
            # Try new format first (Windows/recent versions)
            if "result" in data:
                response_text = data.get("result", "")
                usage = data.get("usage", {})
                tokens = {
                    "input_tokens": usage.get("input_tokens", 0),
                    "output_tokens": usage.get("output_tokens", 0),
                    "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                }
                logger.info(f"[ParseResult] Format: NEW | Response: {str(response_text)[:80]}")
            
            # Fall back to old format
            elif "response" in data:
                response_text = data.get("response", "")
                tokens = {
                    "input_tokens": data.get("input_tokens", 0),
                    "output_tokens": data.get("output_tokens", 0),
                    "total_tokens": data.get("total_tokens", 0)
                }
                logger.info(f"[ParseResult] Format: OLD | Response: {str(response_text)[:80]}")
            
            else:
                logger.error(f"[ParseResult] Unknown format! Keys: {list(data.keys())}")
                # Return response anyway - don't fail
                response_text = str(data)[:1000]
                tokens = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            
            if not response_text:
                logger.warning(f"[ParseResult] Empty response! Keys: {list(data.keys())}")
            
            return response_text, tokens
        
        except json.JSONDecodeError as e:
            logger.error(f"[ParseResult] JSON parse error: {e}")
            logger.error(f"[ParseResult] Raw: {stdout[:300]}")
            # Return raw output if can't parse JSON
            return stdout[:2000], {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    
    async def execute(self, task_id: str, prompt: str, model: str, 
                     timeout: int = EXECUTION_TIMEOUT) -> tuple:
        """
        Execute prompt via Claude CLI
        
        Returns: (response_text, tokens_dict)
        Raises: Exception on timeout/error
        """
        
        logger.info(f"[{task_id}] Executing with model: {model}")
        logger.debug(f"[{task_id}] Prompt: {prompt[:100]}...")
        
        cmd = self._build_command(prompt, model)
        
        try:
            # Start process
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=PIPE,
                text=True
            )
            
            # Track process
            self.pm.add_process(task_id, process)
            
            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except TimeoutExpired:
                logger.warning(f"[{task_id}] Execution timed out after {timeout}s")
                process.kill()
                self.pm.remove_process(task_id)
                raise TimeoutError(f"Claude execution timed out after {timeout} seconds")
            
            # Check for errors
            if process.returncode != 0:
                logger.error(f"[{task_id}] Claude CLI returned error code {process.returncode}")
                logger.error(f"[{task_id}] stderr: {stderr}")
                self.pm.remove_process(task_id)
                raise RuntimeError(f"Claude CLI error: {stderr}")
            
            # Parse output
            response_text, tokens = self._parse_claude_output(stdout)
            
            logger.info(f"[{task_id}] ✓ Success | Tokens: {tokens['total_tokens']}")
            self.pm.remove_process(task_id)
            
            return response_text, tokens
        
        except Exception as e:
            logger.error(f"[{task_id}] Execution failed: {e}")
            self.pm.kill_process(task_id)
            raise

# ═══════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Claude Bridge Server",
    description="Local HTTP bridge to Claude CLI (Max subscription)",
    version="1.0.0"
)

# Initialize managers
process_manager = ProcessManager()
executor = ClaudeExecutor(process_manager)

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Execute a prompt via Claude CLI
    
    Request:
    {
        "prompt": "What is the capital of France?",
        "model": "haiku",
        "task_id": "optional-task-123",
        "timeout": 180
    }
    
    Response:
    {
        "task_id": "optional-task-123",
        "response": "The capital of France is Paris.",
        "tokens": {
            "input_tokens": 12,
            "output_tokens": 8,
            "total_tokens": 20
        },
        "model": "haiku",
        "timestamp": "2026-08-20T15:30:00",
        "status": "success"
    }
    """
    
    # Generate task ID if not provided
    task_id = request.task_id or str(uuid.uuid4())
    timeout = request.timeout or EXECUTION_TIMEOUT
    
    logger.info(f"[{task_id}] /chat request | model={request.model} | prompt_len={len(request.prompt)}")
    
    try:
        # Execute via Claude CLI
        response_text, tokens = await executor.execute(
            task_id=task_id,
            prompt=request.prompt,
            model=request.model,
            timeout=timeout
        )
        
        return ChatResponse(
            task_id=task_id,
            response=response_text,
            tokens=tokens,
            model=request.model,
            timestamp=datetime.now().isoformat(),
            status="success"
        )
    
    except TimeoutError as e:
        logger.error(f"[{task_id}] Timeout error: {e}")
        raise HTTPException(status_code=504, detail=str(e))
    
    except ValueError as e:
        logger.error(f"[{task_id}] Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error(f"[{task_id}] Execution error: {e}")
        raise HTTPException(status_code=500, detail=f"Execution failed: {str(e)}")


@app.post("/stop")
async def stop(request: StopRequest):
    """
    Cancel a running Claude execution
    
    Request:
    {
        "task_id": "optional-task-123"
    }
    
    Response:
    {
        "status": "stopped",
        "task_id": "optional-task-123"
    }
    """
    
    logger.info(f"[{request.task_id}] /stop request")
    
    killed = process_manager.kill_process(request.task_id)
    
    if not killed:
        logger.warning(f"[{request.task_id}] Process not found or already stopped")
    
    return {
        "status": "stopped" if killed else "not_found",
        "task_id": request.task_id,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_tasks": len(process_manager.list_active()),
        "active_task_ids": process_manager.list_active(),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/status/{task_id}")
async def status(task_id: str):
    """Get status of a running task"""
    process = process_manager.get_process(task_id)
    
    if not process:
        return {
            "task_id": task_id,
            "status": "not_found",
            "timestamp": datetime.now().isoformat()
        }
    
    is_running = process.poll() is None
    
    return {
        "task_id": task_id,
        "status": "running" if is_running else "completed",
        "pid": process.pid,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/")
async def root():
    """API documentation"""
    return {
        "service": "Claude Bridge Server",
        "version": "1.0.0",
        "description": "Local HTTP bridge to Claude CLI (Max subscription)",
        "endpoints": {
            "POST /chat": "Execute prompt via Claude CLI",
            "POST /stop": "Cancel running execution",
            "GET /health": "Health check",
            "GET /status/{task_id}": "Check task status",
            "POST /batch": "Execute multiple prompts (future)"
        },
        "models": ["haiku", "sonnet", "opus"],
        "documentation": "http://localhost:8000/docs"
    }


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info("Starting Claude Bridge Server...")
    logger.info(f"Claude CLI path: {CLAUDE_CLI_PATH}")
    logger.info(f"Timeout: {EXECUTION_TIMEOUT}s")
    logger.info("Listening on http://localhost:8000")
    logger.info("Docs: http://localhost:8000/docs")
    
    uvicorn_run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )