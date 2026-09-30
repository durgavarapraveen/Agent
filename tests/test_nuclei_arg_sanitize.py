"""Regression: nuclei's -t flag takes template FILE/DIR paths, not tags. LLM plans
pass "-t cve,misconfig,exposure" (tag names) -> nuclei "[FTL] no templates provided
for scan" rc=1, killing the whole scan. Tags already ride on -tags, so a -t whose
value is a bare tag list must be dropped; real template paths must survive.
"""
import pytest

from core.orchestration.agentic_executor import AgenticExecutor

s = AgenticExecutor._sanitize_tool_args


@pytest.mark.parametrize("args", [
    "-tags cve,misconfig -jsonl -silent -t cve,misconfig,exposure -stats",
    "-jsonl -t=cve,misconfig -stats",
    "-t exposures -tags cve",
])
def test_tag_as_template_path_dropped(args):
    out = s("nuclei", args)
    assert " -t " not in f" {out} " and "-t=" not in out, out


def test_tags_flag_preserved():
    out = s("nuclei", "-tags cve,misconfig,exposure -jsonl -t cve -stats")
    assert "-tags cve,misconfig,exposure" in out and "-stats" in out


@pytest.mark.parametrize("args", [
    "-t /root/nuclei-templates/cves/ -jsonl",
    "-t custom.yaml -silent",
    "-t=exposures/tokens.yml -stats",
])
def test_real_template_paths_survive(args):
    assert "-t" in s("nuclei", args)
