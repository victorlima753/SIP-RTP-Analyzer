from __future__ import annotations

import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import siprtp_v2_performance as performance


class V2PerformanceTests(unittest.TestCase):
    def test_auto_workers_for_small_machine(self) -> None:
        memory = performance.MemoryInfo(total_bytes=8 * 1024**3, available_bytes=4 * 1024**3)

        self.assertEqual(performance.calculate_worker_plan("safe", candidate_count=20, cpu_count=4, memory_info=memory).workers, 1)
        self.assertEqual(performance.calculate_worker_plan("balanced", candidate_count=20, cpu_count=4, memory_info=memory).workers, 2)
        self.assertEqual(performance.calculate_worker_plan("turbo", candidate_count=20, cpu_count=4, memory_info=memory).workers, 3)

    def test_auto_workers_for_6_12_machine(self) -> None:
        memory = performance.MemoryInfo(total_bytes=16 * 1024**3, available_bytes=10 * 1024**3)

        self.assertEqual(performance.calculate_worker_plan("safe", candidate_count=20, cpu_count=12, memory_info=memory).workers, 2)
        self.assertEqual(performance.calculate_worker_plan("balanced", candidate_count=20, cpu_count=12, memory_info=memory).workers, 5)
        self.assertEqual(performance.calculate_worker_plan("turbo", candidate_count=20, cpu_count=12, memory_info=memory).workers, 8)

    def test_workers_clamped_by_candidate_count_and_manual_override(self) -> None:
        memory = performance.MemoryInfo(total_bytes=32 * 1024**3, available_bytes=20 * 1024**3)

        auto_plan = performance.calculate_worker_plan("turbo", candidate_count=2, cpu_count=16, memory_info=memory)
        manual_plan = performance.calculate_worker_plan("balanced", workers="7", candidate_count=20, cpu_count=4, memory_info=memory)

        self.assertEqual(auto_plan.workers, 2)
        self.assertEqual(manual_plan.workers, 7)
        self.assertFalse(manual_plan.auto_workers)


if __name__ == "__main__":
    unittest.main()
