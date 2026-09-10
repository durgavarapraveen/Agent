import json
import logging
from anthropic import Anthropic

logger = logging.getLogger(__name__)

class LLMToolProvider:
    @staticmethod
    def get_all_tools():
        return []

class ClaudeAgentLoop:
    
    def __init__(self, tool_use_executor, invocation_engine, max_iterations=15):
        self.executor = tool_use_executor
        self.invocation_engine = invocation_engine
        self.max_iterations = max_iterations
    
    async def run(self, objective: str, auth_context, session_id: str, tools_list=None):
        logger.info(f"Starting Claude loop for session {session_id} with objective: {objective}")
        
        client = Anthropic()
        messages = [{"role": "user", "content": objective}]
        all_findings = []
        
        for iteration in range(self.max_iterations):
            logger.info(f"[ClaudeAgentLoop] Iteration {iteration + 1}/{self.max_iterations}")
            
            tools = tools_list if tools_list is not None else LLMToolProvider.get_all_tools()
            
            response = client.messages.create(
                model="claude-opus-4-1",
                max_tokens=4096,
                tools=tools,
                messages=messages,
                system="You are a penetration testing agent. Use provided tools to scan and identify vulnerabilities."
            )
            
            messages.append({"role": "assistant", "content": response.content})
            
            tool_results = await self.executor.handle_claude_response(response, auth_context, session_id)
            
            if not tool_results:
                logger.info("[ClaudeAgentLoop] Claude is done. No more tool_use blocks.")
                break
            
            for tr in tool_results:
                findings = tr["result"].get("findings", {})
                if findings:
                    all_findings.append(findings)
            
            tool_blocks = [
                {
                    "type": "tool_result",
                    "tool_use_id": result["tool_use_id"],
                    "content": json.dumps(result["result"])
                }
                for result in tool_results
            ]
            
            messages.append({"role": "user", "content": tool_blocks})
            
        logger.info(f"[ClaudeAgentLoop] Loop completed. Collected {len(all_findings)} findings.")
        return all_findings
