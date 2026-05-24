"""
CodeBadger Vulnerability Detection Agent

Uses Qwen-Agent framework + CodeBadger MCP server to perform
repository-level vulnerability detection on test projects.

Usage:
    # Single project:
    python run_codebadger_agent.py --project apache__struts_CVE-2020-17530_2.5.25

    # All projects:
    python run_codebadger_agent.py --all

    # Custom model/server:
    python run_codebadger_agent.py --project <name> --model Qwen/Qwen3-32B --model-server http://localhost:8000/v1

Prerequisites:
    1. CodeBadger server running: cd codebadger && docker compose up -d && python main.py
    2. vLLM serving the model: vllm serve <model> --port 8000
    3. Install deps: pip install qwen-agent mcp
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from threading import Lock

os.environ.setdefault("QWEN_AGENT_MAX_LLM_CALL_PER_RUN", "25")

sys.path.insert(0, str(Path(__file__).parent / "Qwen-Agent"))

from qwen_agent.agents import Assistant
from qwen_agent.utils.output_beautify import typewriter_print


TEST_PROJECTS_DIR = str(Path(__file__).parent.parent / "pecker-3.0-out" / "project_for_test")
RESULTS_DIR = str(Path(__file__).parent / "results")

CODEBADGER_MCP_URL = "http://localhost:4242/mcp"


class TokenTracker:
    """Tracks token usage across multiple OpenAI API calls."""

    def __init__(self):
        self._lock = Lock()
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.call_count = 0

    def add(self, usage):
        with self._lock:
            self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
            self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0
            self.total_tokens += getattr(usage, "total_tokens", 0) or 0
            self.call_count += 1

    def reset(self):
        with self._lock:
            self.prompt_tokens = 0
            self.completion_tokens = 0
            self.total_tokens = 0
            self.call_count = 0

    def to_dict(self):
        with self._lock:
            return {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "llm_call_count": self.call_count,
            }


_token_tracker = TokenTracker()


def _patch_openai_for_token_tracking():
    """Monkey-patch the OAI LLM class to capture token usage from responses."""
    from qwen_agent.llm.oai import TextChatAtOAI

    original_init = TextChatAtOAI.__init__

    def patched_init(self, cfg=None):
        original_init(self, cfg)
        original_chat_create = self._chat_complete_create

        def tracked_chat_create(*args, **kwargs):
            stream = kwargs.get("stream", False)
            if stream:
                kwargs.setdefault("stream_options", {"include_usage": True})
            response = original_chat_create(*args, **kwargs)
            if not stream:
                if hasattr(response, "usage") and response.usage:
                    _token_tracker.add(response.usage)
            else:
                response = _wrap_stream_for_usage(response)
            return response

        self._chat_complete_create = tracked_chat_create

    TextChatAtOAI.__init__ = patched_init


def _wrap_stream_for_usage(stream_response):
    """Wrap a streaming response to capture usage from the final chunk."""
    for chunk in stream_response:
        if hasattr(chunk, "usage") and chunk.usage:
            _token_tracker.add(chunk.usage)
        yield chunk


_patch_openai_for_token_tracking()

SYSTEM_PROMPT = """You are a security researcher performing repository-level vulnerability detection.
You have access to CodeBadger, a static analysis tool that provides Code Property Graph (CPG) based analysis capabilities.

Your task: Given a Java project repository, perform a comprehensive security audit to identify vulnerabilities.

## Workflow:
1. First, generate a CPG for the target codebase using `generate_cpg` with source_type="local"
2. Wait for CPG generation to complete by checking status with `get_cpg_status`
3. Get an overview of the codebase with `get_codebase_summary`
4. Identify attack surface by finding taint sources with `find_taint_sources`
5. Find dangerous sinks with `find_taint_sinks`
6. Trace taint flows from sources to sinks with `find_taint_flows`
7. Investigate specific suspicious methods with `get_method_source` and `get_call_graph`
8. Use `get_program_slice` for deeper data dependency analysis when needed

## Output Format:
After your analysis, provide a structured vulnerability report with:
- Vulnerability type (CWE ID if applicable)
- Affected file(s) and method(s)
- Data flow description (source → transformations → sink)
- Severity assessment (Critical/High/Medium/Low)
- Brief explanation of the security impact

Be thorough but focused. Prioritize high-severity issues like:
- Remote Code Execution (RCE)
- SQL Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Deserialization vulnerabilities
- Expression Language injection

IMPORTANT RULES:
- Do NOT repeat the same tool call if it returns empty results. Move on to a different approach.
- After at most 15 tool calls, you MUST stop calling tools and write your final vulnerability report.
- If a tool returns an error, try a different tool or parameter, not the same call again.
- Your final response MUST be a text vulnerability report, not a tool call.
"""


def get_llm_config(model: str, model_server: str, api_key: str) -> dict:
    cfg = {
        "model": model,
        "model_server": model_server,
        "api_key": api_key,
        "generate_cfg": {
            "extra_body": {
                "chat_template_kwargs": {"enable_thinking": False}
            }
        },
    }
    return cfg


def get_mcp_tools(codebadger_url: str) -> list:
    return [
        {
            "mcpServers": {
                "codebadger": {
                    "type": "streamable-http",
                    "url": codebadger_url,
                }
            }
        }
    ]


def create_agent(llm_cfg: dict, codebadger_url: str) -> Assistant:
    tools = get_mcp_tools(codebadger_url)
    return Assistant(
        llm=llm_cfg,
        function_list=tools,
        system_message=SYSTEM_PROMPT,
        name="CodeBadger Vulnerability Detector",
        description="Performs repository-level vulnerability detection using CPG-based static analysis",
    )


def wait_for_cpg(codebadger_url: str, project_path: str, language: str = "java",
                  timeout: int = 900, poll_interval: int = 10) -> str:
    """Generate CPG and wait for it to be ready. Returns codebase_hash."""
    import httpx

    mcp_url = codebadger_url

    print(f"[*] Generating CPG for: {project_path}")

    # Call generate_cpg via MCP
    with httpx.Client(timeout=30) as client:
        # Use the MCP streamable-http endpoint to call generate_cpg
        # We'll use the fastmcp Client for this
        pass

    # Use fastmcp Client directly for CPG generation
    import asyncio
    from fastmcp import Client

    async def _generate_and_wait():
        async with Client(mcp_url) as mcp_client:
            # Generate CPG
            result = await mcp_client.call_tool("generate_cpg", {
                "source_type": "local",
                "source_path": project_path,
                "language": language,
            })
            # Extract codebase_hash from result
            import json as _json
            content_text = result.content[0].text
            data = _json.loads(content_text)
            codebase_hash = data.get("codebase_hash")
            if not codebase_hash:
                raise RuntimeError(f"No codebase_hash in response: {data}")

            print(f"[*] CPG generation started. Hash: {codebase_hash}")

            if data.get("status") in ("ready", "cached"):
                print(f"[*] CPG already ready!")
                return codebase_hash

            # Poll for completion
            elapsed = 0
            while elapsed < timeout:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                status_result = await mcp_client.call_tool("get_cpg_status", {
                    "codebase_hash": codebase_hash,
                })
                status_text = status_result.content[0].text
                status_data = _json.loads(status_text)
                status = status_data.get("status", "unknown")

                print(f"[*]   CPG status: {status} ({elapsed}s elapsed)")

                if status in ("ready", "cached"):
                    print(f"[*] CPG ready!")
                    return codebase_hash
                elif status == "failed":
                    error = status_data.get("error", "unknown error")
                    raise RuntimeError(f"CPG generation failed: {error}")

            raise RuntimeError(f"CPG generation timed out after {timeout}s")

    return asyncio.run(_generate_and_wait())


def extract_vulnerabilities(response_text: str) -> dict:
    """Extract vulnerability detection results from the agent's response."""
    vuln_found = False
    vuln_paths = []

    if not response_text:
        return {"detected": False, "vulnerabilities": []}

    text_lower = response_text.lower()

    has_vuln_indicators = any(kw in text_lower for kw in [
        "vulnerability", "cve-", "cwe-", "injection", "rce",
        "remote code execution", "path traversal", "ssrf",
        "deserialization", "critical", "high severity",
        "sql injection", "xss", "command injection",
    ])
    has_no_vuln_indicators = any(kw in text_lower for kw in [
        "no vulnerabilities found", "no significant vulnerabilities",
        "no critical vulnerabilities", "no issues found",
        "could not identify any vulnerabilities",
    ])

    if has_vuln_indicators and not has_no_vuln_indicators:
        vuln_found = True

    # Extract file paths mentioned as vulnerable
    file_patterns = re.findall(
        r'(?:affected|vulnerable|file|path|location)[:\s]*[`"\']*([A-Za-z0-9_/\\.\-]+\.java)[`"\']*',
        response_text, re.IGNORECASE
    )
    # Also match patterns like "src/main/java/..."
    java_paths = re.findall(
        r'((?:src/)?(?:main|test)/(?:java/)?[A-Za-z0-9_/]+\.java)',
        response_text
    )
    # Patterns like com.package.ClassName
    class_patterns = re.findall(
        r'((?:[a-z][a-z0-9]*\.)+[A-Z][A-Za-z0-9]*)',
        response_text
    )

    all_paths = list(dict.fromkeys(file_patterns + java_paths))
    vuln_classes = list(dict.fromkeys(class_patterns[:20]))

    # Extract CWE/CVE IDs
    cwe_ids = list(dict.fromkeys(re.findall(r'CWE-\d+', response_text, re.IGNORECASE)))
    cve_ids = list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', response_text, re.IGNORECASE)))

    # Extract severity
    severities = re.findall(r'\b(Critical|High|Medium|Low)\b', response_text, re.IGNORECASE)
    max_severity = "Unknown"
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for s in severities:
        if severity_order.get(s.lower(), 0) > severity_order.get(max_severity.lower(), 0):
            max_severity = s.capitalize()

    return {
        "detected": vuln_found,
        "max_severity": max_severity if vuln_found else "N/A",
        "cwe_ids": cwe_ids,
        "cve_ids": cve_ids,
        "vulnerable_files": all_paths,
        "vulnerable_classes": vuln_classes,
    }


def run_detection(agent: Assistant, project_path: str, project_name: str,
                  codebadger_url: str, llm_cfg: dict = None) -> dict:
    """Run vulnerability detection on a single project."""

    print(f"\n{'='*70}")
    print(f"[*] Analyzing: {project_name}")
    print(f"[*] Path: {project_path}")
    print(f"{'='*70}\n")

    _token_tracker.reset()
    start_time = time.time()

    # Phase 1: Generate CPG and wait (done in Python, not by the LLM)
    try:
        codebase_hash = wait_for_cpg(codebadger_url, project_path)
    except Exception as e:
        print(f"[!] CPG generation failed: {e}")
        elapsed = round(time.time() - start_time, 2)
        return {
            "project": project_name,
            "path": project_path,
            "elapsed_seconds": elapsed,
            "token_usage": _token_tracker.to_dict(),
            "vulnerabilities": {"detected": False},
            "response": "",
            "error": f"CPG generation failed: {e}",
            "full_conversation": [],
        }

    # Phase 2: Let the agent analyze using the ready CPG
    query = (
        f"The CPG for the following Java project is already generated and ready.\n"
        f"Project: {project_name}\n"
        f"Path: {project_path}\n"
        f"codebase_hash: {codebase_hash}\n\n"
        f"The CPG is READY (status='ready'). Do NOT call generate_cpg or get_cpg_status.\n"
        f"Start directly with analysis:\n"
        f"1. get_codebase_summary with codebase_hash='{codebase_hash}'\n"
        f"2. find_taint_sources\n"
        f"3. find_taint_sinks\n"
        f"4. find_taint_flows\n"
        f"5. Investigate suspicious methods with get_method_source and get_call_graph\n\n"
        f"After analysis, provide your vulnerability findings in the structured format."
    )

    messages = [{"role": "user", "content": query}]

    response_text = ""
    final_response = []

    for response in agent.run(messages):
        final_response = response

    # Extract all text from assistant messages (from tool-calling phase)
    all_text_parts = []
    for m in final_response:
        if m.get("role") == "assistant":
            content = m.get("content", "")
            fc = m.get("function_call")
            if not fc and isinstance(content, str) and content.strip():
                all_text_parts.append(content)

    # If no text output yet, force a summary by doing one more LLM call without tools
    if not all_text_parts:
        print("[*] No text output from tool phase. Requesting final report...")
        summary_messages = messages + final_response + [
            {"role": "user", "content": (
                "Based on all the analysis results above, write your final vulnerability report now. "
                "Do NOT call any more tools. Just provide your findings as text."
            )}
        ]
        from qwen_agent.llm import get_chat_model
        llm = get_chat_model(llm_cfg)
        last_response = None
        for chunk in llm.chat(messages=summary_messages, stream=False):
            last_response = chunk
        if last_response and isinstance(last_response, dict):
            content = last_response.get("content", "")
            if isinstance(content, str) and content.strip():
                all_text_parts.append(content)
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        all_text_parts.append(item["text"])
            final_response.append(last_response)

    response_text = "\n".join(all_text_parts)
    elapsed = time.time() - start_time

    vulnerabilities = extract_vulnerabilities(response_text)
    token_usage = _token_tracker.to_dict()

    result = {
        "project": project_name,
        "path": project_path,
        "codebase_hash": codebase_hash,
        "elapsed_seconds": round(elapsed, 2),
        "token_usage": token_usage,
        "vulnerabilities": vulnerabilities,
        "response": response_text,
        "full_conversation": final_response,
    }

    print(f"\n[*] Completed in {elapsed:.1f}s")
    print(f"[*] Tokens: {token_usage['total_tokens']} total "
          f"({token_usage['prompt_tokens']} prompt + {token_usage['completion_tokens']} completion) "
          f"in {token_usage['llm_call_count']} calls")
    print(f"[*] Vulnerability detected: {vulnerabilities['detected']}")
    if vulnerabilities.get('vulnerable_files'):
        print(f"[*] Vulnerable files: {vulnerabilities['vulnerable_files'][:5]}")

    return result


def parse_project_name(project_dir_name: str) -> dict:
    """Parse project directory name like 'apache__struts_CVE-2020-17530_2.5.25'"""
    parts = project_dir_name.split("_CVE-")
    if len(parts) == 2:
        repo = parts[0].replace("__", "/")
        cve_and_version = parts[1]
        cve_parts = cve_and_version.split("_", 1)
        cve_id = f"CVE-{cve_parts[0]}"
        version = cve_parts[1] if len(cve_parts) > 1 else "unknown"
        return {"repo": repo, "cve": cve_id, "version": version}
    return {"repo": project_dir_name, "cve": "unknown", "version": "unknown"}


def main():
    parser = argparse.ArgumentParser(description="CodeBadger Vulnerability Detection Agent")
    parser.add_argument("--project", type=str, help="Project directory name to analyze")
    parser.add_argument("--all", action="store_true", help="Analyze all test projects")
    parser.add_argument("--task-id", type=str, default=None,
                        help="Task ID for organizing results (default: auto-generated)")
    parser.add_argument("--model", type=str, default="Qwen/Qwen3-32B",
                        help="Model name (default: Qwen/Qwen3-32B)")
    parser.add_argument("--model-server", type=str, default="http://localhost:8000/v1",
                        help="vLLM API base URL (default: http://localhost:8000/v1)")
    parser.add_argument("--api-key", type=str, default="EMPTY",
                        help="API key (default: EMPTY for local vLLM)")
    parser.add_argument("--codebadger-url", type=str, default=CODEBADGER_MCP_URL,
                        help="CodeBadger MCP server URL")
    parser.add_argument("--output-dir", type=str, default=RESULTS_DIR,
                        help="Base output directory for results")
    parser.add_argument("--projects-dir", type=str, default=TEST_PROJECTS_DIR,
                        help="Directory containing test projects")

    args = parser.parse_args()

    # Generate task_id if not provided
    if args.task_id:
        task_id = args.task_id
    else:
        model_short = args.model.split("/")[-1].lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        task_id = f"{model_short}_{timestamp}"

    task_dir = os.path.join(args.output_dir, task_id)
    os.makedirs(task_dir, exist_ok=True)

    llm_cfg = get_llm_config(args.model, args.model_server, args.api_key)
    print(f"[*] Task ID: {task_id}")
    print(f"[*] Results dir: {task_dir}")
    print(f"[*] LLM config: model={args.model}, server={args.model_server}")
    print(f"[*] CodeBadger MCP: {args.codebadger_url}")

    agent = create_agent(llm_cfg, args.codebadger_url)

    if args.project:
        projects = [args.project]
    elif args.all:
        projects = sorted(os.listdir(args.projects_dir))
    else:
        parser.error("Specify --project <name> or --all")
        return

    all_results = []
    for project_name in projects:
        project_path = os.path.join(args.projects_dir, project_name)
        if not os.path.isdir(project_path):
            print(f"[!] Skipping {project_name}: not a directory")
            continue

        try:
            result = run_detection(agent, project_path, project_name, args.codebadger_url, llm_cfg)
            all_results.append(result)

            # Save per-project results in results/{task_id}/{project_name}/
            project_result_dir = os.path.join(task_dir, project_name)
            os.makedirs(project_result_dir, exist_ok=True)

            # Save metrics (lightweight, no conversation log)
            metrics = {
                "project": project_name,
                "elapsed_seconds": result["elapsed_seconds"],
                "token_usage": result["token_usage"],
                "vulnerabilities": result["vulnerabilities"],
            }
            metrics_file = os.path.join(project_result_dir, "metrics.json")
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(metrics, f, ensure_ascii=False, indent=2)

            # Save full report text
            report_file = os.path.join(project_result_dir, "report.md")
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(f"# Vulnerability Report: {project_name}\n\n")
                f.write(result.get("response", "") or "(no report generated)")

            # Save full conversation log (for debugging)
            conv_file = os.path.join(project_result_dir, "conversation.json")
            with open(conv_file, "w", encoding="utf-8") as f:
                json.dump(result["full_conversation"], f, ensure_ascii=False, indent=2)

            print(f"[*] Saved: {project_result_dir}/")

        except Exception as e:
            print(f"[!] Error analyzing {project_name}: {e}")
            all_results.append({
                "project": project_name,
                "error": str(e),
                "elapsed_seconds": 0,
                "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "llm_call_count": 0},
                "vulnerabilities": {"detected": False},
            })

    # Save task-level summary
    total_tokens = sum(r.get("token_usage", {}).get("total_tokens", 0) for r in all_results)
    total_time = sum(r.get("elapsed_seconds", 0) for r in all_results)
    detected_count = sum(1 for r in all_results if r.get("vulnerabilities", {}).get("detected", False))

    summary = {
        "task_id": task_id,
        "timestamp": datetime.now().isoformat(),
        "model": args.model,
        "model_server": args.model_server,
        "codebadger_url": args.codebadger_url,
        "total_projects": len(projects),
        "completed": len([r for r in all_results if "error" not in r]),
        "failed": len([r for r in all_results if "error" in r]),
        "detected_vulnerabilities": detected_count,
        "total_elapsed_seconds": round(total_time, 2),
        "total_tokens": total_tokens,
        "per_project": [
            {
                "project": r["project"],
                "elapsed_seconds": r.get("elapsed_seconds", 0),
                "token_usage": r.get("token_usage", {}),
                "vulnerabilities": r.get("vulnerabilities", {}),
                "error": r.get("error"),
            }
            for r in all_results
        ],
    }
    summary_file = os.path.join(task_dir, "summary.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n{'='*70}")
    print(f"[*] Task: {task_id}")
    print(f"[*] Done. {summary['completed']}/{summary['total_projects']} projects analyzed.")
    print(f"[*] Vulnerabilities detected: {detected_count}/{summary['completed']}")
    print(f"[*] Total time: {total_time:.1f}s | Total tokens: {total_tokens}")
    print(f"[*] Results saved to: {task_dir}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
