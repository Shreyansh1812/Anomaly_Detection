Development Roadmap: From Prototype to V1 Log Analysis Engine

Objective
This document outlines the concrete engineering tasks required to evolve the current log analysis prototype into a robust, configurable, and production-ready tool, as defined in the project charter. The focus is on creating a reliable baseline, implementing the advanced layered detection logic, and transforming the output from a simple data dump into actionable intelligence.

Phase 1: Solidify the Baseline & Core Framework (Highest Priority)
Goal: Finalize the simple, rule-based engine to create a complete, shippable product that will serve as the performance benchmark for all future work.

[ ] Finalize Unit Testing:

Implement comprehensive pytest unit tests for WebSecurityAnalyzer and analyze_log_pipeline.

Ensure tests cover all detection patterns, edge cases (empty files, missing columns), and stateful logic (brute-force counters).

Deliverable: A tests/ directory with a passing test suite and >85% code coverage.

[ ] Implement Robust CLI and Configuration:

Refactor hard-coded values (thresholds, top_n) to be loaded from a config.yaml file.

Implement an argparse CLI to allow all config values to be overridden at runtime.

Deliverable: A default config.yaml and a fully functional command-line interface.

[ ] Create Professional Documentation:

Write a comprehensive README.md including sections for Installation, Usage (with CLI examples), Patterns Detected, and a Sample Report.

Generate requirements.txt and requirements-dev.txt.

Deliverable: Complete user-facing documentation.

[ ] Establish Continuous Integration (CI):

Create a .github/workflows/ci.yml pipeline that runs ruff for linting and pytest for testing on every pull request.

Deliverable: A CI workflow that blocks merging of failing branches.

Phase 2: Implement the Advanced Layered Detection Logic
Goal: Enhance the detection engine to be more intelligent and extensible, allowing it to adapt to new log formats without code changes.

[ ] Integrate Level-Based Fallback:

Modify ErrorPatternDetector to perform a case-insensitive check for Level/Severity columns in input data.

If found, count ERROR/FATAL/CRITICAL entries and add them to the report under a level_based_errors key.

Deliverable: The engine can now find errors in logs with a severity field, even if no regex patterns match.

[ ] Implement Config-Driven Custom Patterns:

Refactor ErrorPatternDetector to accept a dictionary of custom regex patterns during initialization.

Update analyze_log_pipeline.py to load these custom patterns from a custom_error_patterns section in config.yaml.

Deliverable: The engine is now fully extensible. New patterns for new log types (like HDFS) can be added via the config file alone.

[ ] Update Test Suite for New Logic:

Add new pytest cases to verify that the level-based fallback and custom pattern loading work as expected.

Include tests to ensure the system falls back gracefully to baseline patterns if the new config sections are absent.

Deliverable: A complete test suite covering all layers of the detection logic.

Phase 3: Transform Reporting from Data to Intelligence
Goal: Evolve the output from a simple list of counts into a valuable, decision-making tool.

[ ] Embed Performance Metrics in Reports:

Add a dedicated "Performance Summary" section to the Markdown report.

This section must display the Precision and Recall of the engine's findings for the executed run (requires a mechanism to compare against a ground truth file).

Deliverable: Reports are now transparent and self-evaluating.

[ ] Generate Actionable Insights:

Instead of just authentication_errors: 46, the report must provide context.

Implement logic to aggregate findings and list the Top 5 Attacking IP Addresses or Top 5 Usernames Targeted.

Deliverable: The report now pinpoints key entities for an analyst to investigate.

[ ] Add a Dynamic Recommendation Engine:

Implement a simple final logic step that generates a human-readable summary and recommendation.

Example: If bruteforce_ips is not empty, recommend investigating and blocking the listed IPs.

Deliverable: The report concludes with a clear, automated suggestion for the next action.
