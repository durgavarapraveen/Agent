import unittest
import uuid

from core.domain.experiment_v2 import SecurityExperiment, ExperimentState
from core.domain.task_state_machine import TaskStateMachine, TaskState
from core.scheduling.experiment_scheduler_v2 import ExperimentScheduler
from core.scheduling.duplicate_detector import DuplicateDetector


class TestExperiment(unittest.TestCase):

    def test_experiment_creation(self):
        exp = SecurityExperiment(
            hypothesis_id="h1",
            endpoint_id="/api/login",
            capability="nmap",
            identity_id="admin",
            priority=0.8,
        )
        self.assertEqual(exp.hypothesis_id, "h1")
        self.assertEqual(exp.endpoint_id, "/api/login")
        self.assertEqual(exp.capability, "nmap")
        self.assertEqual(exp.identity_id, "admin")
        self.assertEqual(exp.priority, 0.8)
        self.assertEqual(exp.state, ExperimentState.CREATED)
        self.assertIsInstance(exp.input_parameters, dict)
        self.assertIsInstance(exp.prerequisites, list)
        self.assertIsInstance(exp.evidence_ids, list)

    def test_experiment_has_uuid(self):
        exp = SecurityExperiment(hypothesis_id="h1", endpoint_id="/api", capability="nmap")
        parsed = uuid.UUID(exp.experiment_id)
        self.assertEqual(str(parsed), exp.experiment_id)


class TestScheduler(unittest.TestCase):

    def _make(self, priority: float, cap: str = "nmap", endpoint: str = "/api") -> SecurityExperiment:
        return SecurityExperiment(
            hypothesis_id="h1", endpoint_id=endpoint, capability=cap,
            identity_id=str(priority), priority=priority,
        )

    def test_scheduler_queues_experiment(self):
        s = ExperimentScheduler()
        exp = self._make(0.5)
        self.assertTrue(s.queue(exp))
        self.assertEqual(s.size(), 1)

    def test_scheduler_next_returns_highest_priority(self):
        s = ExperimentScheduler()
        s.queue(self._make(0.5, endpoint="/a"))
        s.queue(self._make(0.95, endpoint="/b"))
        s.queue(self._make(0.72, endpoint="/c"))
        top = s.next()
        self.assertAlmostEqual(top.priority, 0.95)

    def test_scheduler_returns_experiments_in_priority_order(self):
        s = ExperimentScheduler()
        s.queue(self._make(0.5, endpoint="/a"))
        s.queue(self._make(0.95, endpoint="/b"))
        s.queue(self._make(0.72, endpoint="/c"))
        priorities = [s.next().priority for _ in range(3)]
        self.assertEqual(priorities, [0.95, 0.72, 0.5])

    def test_scheduler_max_queue_size_limit(self):
        s = ExperimentScheduler(max_queue_size=2)
        self.assertTrue(s.queue(self._make(0.5, endpoint="/a")))
        self.assertTrue(s.queue(self._make(0.6, endpoint="/b")))
        self.assertFalse(s.queue(self._make(0.7, endpoint="/c")))
        self.assertEqual(s.size(), 2)


class TestTaskStateMachine(unittest.TestCase):

    def test_task_state_machine_valid_transition(self):
        sm = TaskStateMachine("t1")
        self.assertEqual(sm.state, TaskState.CREATED)
        sm.transition(TaskState.READY)
        self.assertEqual(sm.state, TaskState.READY)
        sm.transition(TaskState.RUNNING)
        self.assertEqual(sm.state, TaskState.RUNNING)
        sm.transition(TaskState.SUCCEEDED)
        self.assertEqual(sm.state, TaskState.SUCCEEDED)

    def test_task_state_machine_invalid_transition_raises(self):
        sm = TaskStateMachine("t1")
        with self.assertRaises(ValueError) as ctx:
            sm.transition(TaskState.SUCCEEDED)
        self.assertIn("Valid transitions", str(ctx.exception))

    def test_task_state_machine_can_transition_check(self):
        sm = TaskStateMachine("t1")
        self.assertTrue(sm.can_transition(TaskState.READY))
        self.assertFalse(sm.can_transition(TaskState.SUCCEEDED))
        self.assertFalse(sm.can_transition(TaskState.RUNNING))


class TestDuplicateDetector(unittest.TestCase):

    def test_duplicate_detector_same_params_same_fingerprint(self):
        d = DuplicateDetector()
        fp1 = d.fingerprint("nmap", "example.com", "/api", "admin", {"port": 80})
        fp2 = d.fingerprint("nmap", "example.com", "/api", "admin", {"port": 80})
        self.assertEqual(fp1, fp2)

    def test_duplicate_detector_different_identity_different_fingerprint(self):
        d = DuplicateDetector()
        fp1 = d.fingerprint("nmap", "example.com", "/api", "admin", {"port": 80})
        fp2 = d.fingerprint("nmap", "example.com", "/api", "guest", {"port": 80})
        self.assertNotEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()
