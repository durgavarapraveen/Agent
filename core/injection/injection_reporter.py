from core.injection.models import InjectionTestMatrix

class InjectionReporter:
    @staticmethod
    def generate_report(matrix: InjectionTestMatrix) -> str:
        
        def safe_get(type_key: str, status_key: str) -> int:
            if type_key in matrix.status_by_type:
                return matrix.status_by_type[type_key].get(status_key, 0)
            return 0
            
        report = f"""INJECTION_MATRIX
endpoints={matrix.endpoints}
eligible_parameters={matrix.eligible_parameters}

SQLI
tested={safe_get('sqli', 'tested')}
confirmed={safe_get('sqli', 'confirmed')}
rejected={safe_get('sqli', 'rejected')}
blocked={safe_get('sqli', 'blocked')}

XSS
reflected_tested={safe_get('xss_reflected', 'tested')}
reflected_confirmed={safe_get('xss_reflected', 'confirmed')}
dom_tested={safe_get('xss_dom', 'tested')}
dom_confirmed={safe_get('xss_dom', 'confirmed')}
stored_tested={safe_get('xss_stored', 'tested')}
stored_confirmed={safe_get('xss_stored', 'confirmed')}

SSTI
tested={safe_get('ssti', 'tested')}
confirmed={safe_get('ssti', 'confirmed')}
rejected={safe_get('ssti', 'rejected')}

COMMAND_INJECTION
tested={safe_get('command', 'tested')}
confirmed={safe_get('command', 'confirmed')}

PATH_TRAVERSAL
tested={safe_get('path_traversal', 'tested')}
confirmed={safe_get('path_traversal', 'confirmed')}
"""
        return report
