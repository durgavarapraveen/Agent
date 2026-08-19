from typing import List, Dict, Any
import logging

from core.models import Task, TaskStatus, TaskProposal
from llm.base import LLMProvider

logger = logging.getLogger(__name__)

class Planner:
    """Plans what work needs to be done."""
    
    def __init__(self, llm_provider: LLMProvider):
        self.llm_provider = llm_provider
    
    async def create_initial_plan(self, objective: str, target_type: str) -> List[Task]:
        """Create initial plan based on objective and target type."""
        tasks = []
        
        logger.info(f"Creating plan for objective: {objective}")
        logger.info(f"Target type: {target_type}")
        
        if target_type == "WEB":
            # Web assessment plan
            tasks.append(Task(
                title="Reconnaissance",
                description="Map the target's attack surface",
                objective="Discover endpoints, technologies, and services",
                capability="reconnaissance",
                priority=10
            ))
            tasks.append(Task(
                title="Vulnerability Scanning",
                description="Detect security vulnerabilities",
                objective="Find security flaws in the application",
                capability="vulnerability_scanning",
                priority=9
            ))
            
            tasks.append(Task(
                title="Dependency Analysis",
                description="Check for vulnerable dependencies",
                objective="Identify vulnerable packages",
                capability="dependency_analysis",
                priority=8
            ))
            
            tasks.append(Task(
                title="Web Server Analysis",
                description="Scan web server configuration",
                objective="Find server misconfigurations",
                capability="web_server_analysis",
                priority=7
            ))
            
            tasks.append(Task(
                title="Comprehensive Reconnaissance",
                description="Full target discovery and analysis",
                objective="Execute all reconnaissance phases",
                capability="comprehensive_recon",
                priority=10
            ))
            
            tasks.append(Task(
                title="Subdomain Discovery",
                description="Enumerate subdomains using multiple sources",
                objective="Find all subdomains and related assets",
                capability="subdomain_discovery",
                priority=8
            ))

            tasks.append(Task(
                title="Port and Service Scanning",
                description="Discover open ports and running services",
                objective="Map network services and versions",
                capability="port_scanning",
                priority=8
            ))

            tasks.append(Task(
                title="Directory and Content Discovery",
                description="Bruteforce directories and hidden content",
                objective="Find hidden paths and endpoints",
                capability="directory_bruteforce",
                priority=7
            ))

            tasks.append(Task(
                title="Technology Stack Identification",
                description="Identify web technologies and frameworks",
                objective="Detect software, versions, and CVEs",
                capability="tech_detection",
                priority=7
            ))

            tasks.append(Task(
                title="Visual Reconnaissance",
                description="Capture screenshots of web applications",
                objective="Visual assessment and reconnaissance",
                capability="screenshot",
                priority=6
            ))

            tasks.append(Task(
                title="Vulnerability Detection",
                description="Scan for known vulnerabilities",
                objective="Identify security issues automatically",
                capability="vulnerability_detection",
                priority=6
            ))
        
        elif target_type == "SOURCE":
            # Source code analysis plan
            tasks.append(Task(
                title="Source Code Analysis",
                description="Analyze source code for security issues",
                objective="Identify security flaws and vulnerabilities in code",
                capability="source_analysis",
                priority=10
            ))
        
        elif target_type == "DEMO":
            # Demo mode plan
            tasks.append(Task(
                title="Reconnaissance",
                description="Simulate reconnaissance",
                objective="Simulate discovering target information",
                capability="reconnaissance",
                priority=10
            ))
        
        return tasks
    
    async def create_tasks_from_proposals(self, proposals: List[TaskProposal]) -> List[Task]:
        """Convert task proposals into actual tasks."""
        tasks = []
        
        for proposal in proposals:
            task = Task(
                title=proposal.objective,
                description=f"Proposed by {proposal.proposed_by}",
                objective=proposal.objective,
                capability=proposal.capability,
                priority=proposal.priority,
                created_by=proposal.proposed_by
            )
            tasks.append(task)
            logger.info(f"Created task from proposal: {task.capability}")
        
        return tasks
    
    async def evaluate_replanning_needed(self, 
                                         discoveries: List[Dict[str, Any]],
                                         findings: List,
                                         completed_tasks: int) -> bool:
        """Determine if replanning is needed."""
        # Simple heuristic: replan if significant discoveries made
        if len(discoveries) > 0:
            return True
        
        return False
    
    async def create_validation_plan(self, findings: List) -> List[Task]:
        """Create plan for validating findings."""
        tasks = []
        
        # Create validation task for each finding
        for i, finding in enumerate(findings):
            if hasattr(finding, 'status') and 'CANDIDATE' in str(finding.status):
                task = Task(
                    title=f"Validate: {finding.title}",
                    description=f"Validate finding {finding.finding_id}",
                    objective="Confirm or reject the finding",
                    capability="validation",
                    priority=7,
                    created_by="validation_planner"
                )
                tasks.append(task)
        
        return tasks
    
    async def create_correlation_plan(self, findings: List) -> List[Task]:
        """Create plan for correlating findings."""
        if not findings:
            return []
        
        return [Task(
            title="Correlate Findings",
            description="Identify relationships between findings",
            objective="Find potential attack paths and relationships",
            capability="correlation",
            priority=6,
            created_by="correlation_planner"
        )]
    
    async def create_reporting_plan(self) -> List[Task]:
        """Create plan for final reporting."""
        return [Task(
            title="Generate Report",
            description="Generate security assessment report",
            objective="Produce final security report",
            capability="reporting",
            priority=1,  # Last task
            created_by="reporting_planner"
        )]
