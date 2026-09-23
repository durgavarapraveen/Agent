from core.access_control.base import AccessControlTest, AuthorizationOracle
from core.common import target_shape as ts
import copy
import re

class IdorTest(AccessControlTest):
    @staticmethod
    def _peer_object_ids(identities, exclude_uid) -> list:
        """Best-effort real object ids belonging to OTHER identities, for
        cross-identity substitution (a genuine cross-user object beats a blind
        integer increment)."""
        out = []
        for uid, iden in identities.items():
            if uid == exclude_uid:
                continue
            attrs = getattr(iden, "attributes", {}) or {}
            for cand in (attrs.get("user_id"), attrs.get("id"), attrs.get("object_id"),
                         attrs.get("account_id"), getattr(iden, "id", None), uid):
                if cand and ts.looks_like_id(str(cand)):
                    out.append(str(cand))
        return out

    def execute(self, request_node, identities) -> dict:
        results = {}

        # We need an authenticated, non-privileged user to test IDOR — selected by
        # relative privilege rank, not a "standard" literal.
        standard_users = [uid for uid, iden in identities.items() if ts.role_rank(iden.role) == 1]
        if not standard_users:
            return results

        owner_id = standard_users[0]

        # Determine if the request has an ID to mutate.
        path = request_node.get("path", "")

        # Primary: ANY path segment that looks like an id (numeric, UUID, ObjectId,
        # ULID, hex, hashid) is an IDOR candidate — not only segments next to a
        # fixed resource-noun list, and not only trailing integers.
        id_segments = ts.id_path_segments(path)
        original_id = ""
        mutated_id = ""
        mutated_path = ""

        if id_segments:
            # target the last id-like segment (usually the resource id)
            _, original_id = id_segments[-1]
            # Prefer substituting another identity's REAL object id (proves
            # cross-user access) over a blind increment.
            peer_ids = [pid for pid in self._peer_object_ids(identities, owner_id) if pid != original_id]
            if peer_ids:
                mutated_id = peer_ids[0]
            elif ts.is_numeric_id(original_id):
                mutated_id = str(int(original_id) + 1)
            else:
                # opaque/UUID id with no known peer: perturb deterministically
                mutated_id = original_id + "-mutated"
            # replace the specific occurrence of that segment in the path
            seg_pat = re.compile(r'(?<=/)' + re.escape(original_id) + r'(?=/|$)')
            mutated_path = seg_pat.sub(mutated_id, path, count=1)
            if mutated_path == path:  # substitution failed — nothing safe to test
                return results
        else:
            # Fallback: trailing generic id (numeric or opaque) via looks_like_id.
            match = re.search(r'/([^/]+)/?$', path)
            if not match or not ts.looks_like_id(match.group(1)):
                return results
            original_id = match.group(1)
            peer_ids = [pid for pid in self._peer_object_ids(identities, owner_id) if pid != original_id]
            if peer_ids:
                mutated_id = peer_ids[0]
            elif ts.is_numeric_id(original_id):
                mutated_id = str(int(original_id) + 1)
            else:
                mutated_id = original_id + "-mutated"
            mutated_path = path[:match.start(1)] + mutated_id + path[match.end(1):]

        baseline_resp = self.replayer.replay(request_node, identity_id=owner_id)
        if not baseline_resp or baseline_resp["status"] >= 400:
            return results
            
        # Mutate the request
        mutated_request = copy.deepcopy(request_node)
        mutated_request["path"] = mutated_path
        
        mutated_resp = self.replayer.replay(mutated_request, identity_id=owner_id)
        
        result = AuthorizationOracle.compare(
            baseline_resp["status"], 
            mutated_resp["status"], 
            baseline_resp["body"], 
            mutated_resp["body"]
        )
        
        results["IDOR"] = result
        return results
