"""Browser smoke test against a real joined evaluation artifact."""
import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--screenshot", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.trace.read_text().splitlines() if line.strip()]
    chosen = next(row for row in rows if row.get("flow_findings") and row.get("rewritten_action") and row.get("execution"))
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100}, device_scale_factor=1)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(args.url, wait_until="networkidle")
        page.set_input_files("#file", str(args.trace.resolve()))
        page.wait_for_function("document.querySelector('#run').options.length > 0")
        page.select_option("#run", chosen["run_id"])
        page.get_by_role("button", name="Interventions only").click()
        page.get_by_text("Verified replacement action", exact=True).first.wait_for()
        assert page.get_by_text("Observed simulator execution", exact=True).count() > 0
        assert page.get_by_text("Protected data: source", exact=False).count() > 0
        assert not errors, errors
        args.screenshot.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(args.screenshot), full_page=False)
        print(json.dumps({"browser_errors": errors, "run": chosen["run_id"], "screenshot": str(args.screenshot)}))
        browser.close()


if __name__ == "__main__":
    main()
