from typing import Dict, List, Tuple


JUICE_SHOP_CHALLENGES: List[Tuple[str, str, int]] = [
    # (challenge_name, owasp_category, difficulty_stars)
    # A01:2021 - Broken Access Control
    ("Admin Section", "broken_access_control", 1),
    ("Five-Star Feedback", "broken_access_control", 2),
    ("Forged Feedback", "broken_access_control", 3),
    ("Forged Review", "broken_access_control", 3),
    ("Manipulate Basket", "broken_access_control", 3),
    ("Product Tampering", "broken_access_control", 3),
    ("View Basket", "broken_access_control", 2),
    ("Easter Egg", "broken_access_control", 4),
    ("Forgotten Developer Backup", "broken_access_control", 4),
    ("Forgotten Sales Backup", "broken_access_control", 4),
    ("GDPR Data Erasure", "broken_access_control", 3),
    ("Login Admin", "broken_access_control", 2),
    ("Login Amy", "broken_access_control", 3),
    ("Login Bender", "broken_access_control", 3),
    ("Login Jim", "broken_access_control", 3),
    ("Login MC SafeSearch", "broken_access_control", 2),
    ("Login Support Team", "broken_access_control", 6),
    ("Mint the Honey Pot", "broken_access_control", 4),
    ("Nested Easter Egg", "broken_access_control", 4),
    ("Reset Jim's Password", "broken_access_control", 3),
    ("SSRF", "broken_access_control", 6),
    ("Two Factor Authentication", "broken_access_control", 5),
    ("Upload Size", "broken_access_control", 3),
    ("Upload Type", "broken_access_control", 3),
    ("Expired Coupon", "broken_access_control", 4),
    ("Allowlist Bypass", "broken_access_control", 4),

    # A02:2021 - Cryptographic Failures
    ("Confidential Document", "cryptographic_failures", 1),
    ("Exposed Metrics", "cryptographic_failures", 1),
    ("Weird Crypto", "cryptographic_failures", 2),
    ("Nested Easter Egg Crypto", "cryptographic_failures", 4),
    ("Premium Paywall", "cryptographic_failures", 6),
    ("Privacy Policy Inspection", "cryptographic_failures", 3),
    ("Successful RCE DoS", "cryptographic_failures", 6),

    # A03:2021 - Injection
    ("SQL Injection Login", "injection", 1),
    ("SQL Injection Schema", "injection", 3),
    ("SQL Injection Search", "injection", 2),
    ("Christmas Special", "injection", 4),
    ("Database Schema", "injection", 3),
    ("Ephemeral Accountant", "injection", 4),
    ("NoSQL DoS", "injection", 5),
    ("NoSQL Exfiltration", "injection", 4),
    ("NoSQL Manipulation", "injection", 4),
    ("SSTi", "injection", 6),
    ("Server-side XSS Protection", "injection", 4),
    ("Video XSS", "injection", 6),

    # A04:2021 - Insecure Design
    ("CAPTCHA Bypass", "insecure_design", 3),
    ("Email Leak", "insecure_design", 5),
    ("Extra Language", "insecure_design", 5),
    ("Leaked Access Log", "insecure_design", 4),
    ("Leaked Unsafe Product", "insecure_design", 4),
    ("Legacy Typosquatting", "insecure_design", 4),
    ("Mass Dispel", "insecure_design", 3),
    ("Poison Null Byte", "insecure_design", 4),
    ("Repetitive Registration", "insecure_design", 3),
    ("Reset Bender's Password", "insecure_design", 4),
    ("Reset Bjoern's Password", "insecure_design", 5),
    ("Reset Morty's Password", "insecure_design", 5),
    ("Reset Uvogin's Password", "insecure_design", 4),
    ("Security Policy", "insecure_design", 2),
    ("Steganography", "insecure_design", 4),
    ("Supply Chain Attack", "insecure_design", 5),
    ("Typosquatting", "insecure_design", 4),
    ("Unsigned JWT", "insecure_design", 5),
    ("Vulnerable Library", "insecure_design", 4),
    ("Whitelist Bypass", "insecure_design", 4),

    # A05:2021 - Security Misconfiguration
    ("Deprecated Interface", "security_misconfiguration", 2),
    ("Error Handling", "security_misconfiguration", 1),
    ("Login Bjoern", "security_misconfiguration", 4),
    ("Missing Encoding", "security_misconfiguration", 1),
    ("Redirects Tier 1", "security_misconfiguration", 1),
    ("Redirects Tier 2", "security_misconfiguration", 4),
    ("XXE Data Access", "security_misconfiguration", 3),
    ("XXE DoS", "security_misconfiguration", 5),
    ("Arbitrary File Write", "security_misconfiguration", 6),
    ("Cross-Site Imaging", "security_misconfiguration", 5),
    ("HTTP Header XSS", "security_misconfiguration", 3),
    ("Local File Read", "security_misconfiguration", 6),

    # A06:2021 - Vulnerable and Outdated Components
    ("Frontend Typosquatting", "vulnerable_components", 5),
    ("Legacy Typosquatting Component", "vulnerable_components", 4),
    ("Outdated Allowlist", "vulnerable_components", 5),
    ("Supply Chain Component", "vulnerable_components", 5),
    ("Vulnerable Library Component", "vulnerable_components", 4),

    # A07:2021 - Identification and Authentication Failures
    ("Bjoern's Favorite Pet", "auth_failures", 3),
    ("Change Bender's Password", "auth_failures", 5),
    ("GDPR Data Theft", "auth_failures", 4),
    ("Login Credentials", "auth_failures", 2),
    ("Multiples Likes", "auth_failures", 6),
    ("Oauth2 Redirect", "auth_failures", 5),
    ("Password Strength", "auth_failures", 2),
    ("Reset Password via Security Question", "auth_failures", 3),
    ("Two Factor Auth Bypass", "auth_failures", 5),
    ("Weak Password", "auth_failures", 1),

    # A08:2021 - Software and Data Integrity Failures
    ("Forged Signed JWT", "integrity_failures", 6),
    ("JWT Issues 1", "integrity_failures", 3),
    ("JWT Issues 2", "integrity_failures", 5),
    ("Unsigned JWT Integrity", "integrity_failures", 5),

    # A09:2021 - Security Logging and Monitoring Failures
    ("Access Log", "logging_failures", 4),
    ("Monitoring Bypass", "logging_failures", 5),

    # A10:2021 - Server-Side Request Forgery
    ("SSRF Redirect", "ssrf", 6),
    ("SSRF via Profile Image", "ssrf", 6),

    # XSS Challenges (cross-cutting)
    ("API-Only XSS", "xss", 3),
    ("Bonus Payload", "xss", 1),
    ("Client-side XSS Protection", "xss", 3),
    ("DOM XSS", "xss", 1),
    ("Reflected XSS", "xss", 2),
    ("Stored XSS", "xss", 4),
    ("Reflected XSS Tier 2", "xss", 4),
    ("Stored XSS Tier 2", "xss", 5),

    # Miscellaneous / Improper Input Validation
    ("Admin Registration", "improper_input", 3),
    ("Deluxe Fraud", "improper_input", 3),
    ("Payback Time", "improper_input", 3),
    ("Wallet Depletion", "improper_input", 5),
    ("Zero Stars", "improper_input", 1),
    ("Blockchain Hype", "improper_input", 5),
    ("CSRF Token Bypass", "improper_input", 4),
    ("Null Byte Injection", "improper_input", 4),
    ("Race Condition", "improper_input", 5),
]

CATEGORY_TO_TEST_ID = {
    "broken_access_control": "access_control.idor",
    "cryptographic_failures": "cryptography.weak_crypto",
    "injection": "input_validation.sqli",
    "insecure_design": "business_logic.design_flaw",
    "security_misconfiguration": "misconfiguration.server",
    "vulnerable_components": "dependency.outdated",
    "auth_failures": "authentication.basic",
    "integrity_failures": "jwt.manipulation",
    "logging_failures": "information_disclosure.logs",
    "ssrf": "ssrf.basic",
    "xss": "xss.reflected",
    "improper_input": "input_validation.general",
}

CHALLENGE_OVERRIDES: Dict[str, str] = {
    "SQL Injection Login": "input_validation.sqli",
    "SQL Injection Schema": "input_validation.sqli",
    "SQL Injection Search": "input_validation.sqli",
    "NoSQL DoS": "input_validation.nosqli",
    "NoSQL Exfiltration": "input_validation.nosqli",
    "NoSQL Manipulation": "input_validation.nosqli",
    "SSTi": "input_validation.ssti",
    "DOM XSS": "xss.dom",
    "Reflected XSS": "xss.reflected",
    "Stored XSS": "xss.stored",
    "Reflected XSS Tier 2": "xss.reflected",
    "Stored XSS Tier 2": "xss.stored",
    "API-Only XSS": "xss.api",
    "Server-side XSS Protection": "xss.server_bypass",
    "Video XSS": "xss.stored",
    "XXE Data Access": "xxe.basic",
    "XXE DoS": "xxe.dos",
    "SSRF": "ssrf.basic",
    "SSRF Redirect": "ssrf.redirect",
    "SSRF via Profile Image": "ssrf.file_upload",
    "CAPTCHA Bypass": "business_logic.captcha",
    "CSRF Token Bypass": "csrf.basic",
    "Forged Signed JWT": "jwt.forgery",
    "JWT Issues 1": "jwt.manipulation",
    "JWT Issues 2": "jwt.manipulation",
    "Unsigned JWT": "jwt.unsigned",
    "Unsigned JWT Integrity": "jwt.unsigned",
    "Race Condition": "race_condition.basic",
    "Arbitrary File Write": "file_upload.arbitrary_write",
    "Local File Read": "path_traversal.lfi",
    "Poison Null Byte": "input_validation.null_byte",
    "Null Byte Injection": "input_validation.null_byte",
    "Successful RCE DoS": "command_injection.rce",
    "Admin Section": "authorization.idor",
    "Admin Registration": "authorization.privilege_escalation",
    "Login Admin": "authentication.brute_force",
    "Login Amy": "authentication.brute_force",
    "Login Bender": "authentication.brute_force",
    "Login Jim": "authentication.brute_force",
    "Login MC SafeSearch": "authentication.brute_force",
    "Login Bjoern": "authentication.brute_force",
    "Login Support Team": "authentication.brute_force",
    "Login Credentials": "authentication.default_creds",
    "Weak Password": "authentication.weak_password",
    "Password Strength": "authentication.weak_password",
    "Two Factor Authentication": "authentication.mfa_bypass",
    "Two Factor Auth Bypass": "authentication.mfa_bypass",
    "Manipulate Basket": "authorization.idor",
    "View Basket": "authorization.idor",
    "Five-Star Feedback": "authorization.idor",
    "Forged Feedback": "authorization.idor",
    "Forged Review": "authorization.idor",
    "Product Tampering": "authorization.mass_assignment",
    "Payback Time": "business_logic.price_manipulation",
    "Deluxe Fraud": "business_logic.price_manipulation",
    "Wallet Depletion": "business_logic.price_manipulation",
    "Zero Stars": "input_validation.general",
    "Error Handling": "information_disclosure.error_messages",
    "Exposed Metrics": "information_disclosure.metrics",
    "Confidential Document": "information_disclosure.file_exposure",
    "Missing Encoding": "misconfiguration.encoding",
    "Deprecated Interface": "misconfiguration.deprecated_api",
    "Redirects Tier 1": "misconfiguration.open_redirect",
    "Redirects Tier 2": "misconfiguration.open_redirect",
    "HTTP Header XSS": "xss.header_injection",
    "Cross-Site Imaging": "misconfiguration.cors",
    "Oauth2 Redirect": "authentication.oauth_redirect",
    "Blockchain Hype": "business_logic.design_flaw",
}


class JuiceShopChallengeMapper:
    def __init__(self):
        self.challenges = list(JUICE_SHOP_CHALLENGES)
        self._mapping: Dict[str, str] = {}

    def map_challenges_to_tests(self) -> Dict[str, str]:
        if self._mapping:
            return dict(self._mapping)

        for name, category, difficulty in self.challenges:
            if name in CHALLENGE_OVERRIDES:
                test_id = CHALLENGE_OVERRIDES[name]
            else:
                test_id = CATEGORY_TO_TEST_ID.get(category, f"{category}.generic")
            self._mapping[name] = test_id

        return dict(self._mapping)

    def get_challenges_for_test(self, test_id: str) -> List[str]:
        mapping = self.map_challenges_to_tests()
        return [name for name, tid in mapping.items() if tid == test_id]

    def get_unique_test_ids(self) -> List[str]:
        mapping = self.map_challenges_to_tests()
        return sorted(set(mapping.values()))

    def get_challenge_count(self) -> int:
        return len(self.challenges)

    def get_challenge_difficulty(self, name: str) -> int:
        for cname, _, diff in self.challenges:
            if cname == name:
                return diff
        return 0
