import argparse
import sys
from text2sql_antipattern.pipeline.engine import run_pipeline


def main():
    parser = argparse.ArgumentParser(
        prog="text2sql-antipattern",
        description="SQL antipattern analysis pipeline for Text-to-SQL datasets"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Run command
    run_parser = subparsers.add_parser(
        "run",
        help="Run the antipattern analysis pipeline"
    )
    run_parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to pipeline configuration YAML file"
    )

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate markdown report from DuckDB metrics"
    )

    report_group = report_parser.add_mutually_exclusive_group(required=True)

    report_group.add_argument(
        "--config",
        help="Path to pipeline configuration YAML file (uses reports config)"
    )

    report_group.add_argument(
        "--database",
        help="Path to DuckDB metrics database"
    )

    report_parser.add_argument(
        "--output",
        required=False,
        help="Output path for markdown report (required with --database)"
    )

    args = parser.parse_args()

    if args.command == "run":
        output_dir = run_pipeline(args.config)
        print(f"\nPipeline completed successfully!")
        print(f"Output directory: {output_dir}")
        return 0

    elif args.command == "report":
        try:
            if hasattr(args, 'config') and args.config:
                import yaml
                import os
                from text2sql_antipattern.output.report import generate_all_reports

                with open(args.config, 'r') as f:
                    config = yaml.safe_load(f)

                output_cfg = config.get("output", {})
                reports_cfg = output_cfg.get("reports", {})

                duckdb_path = output_cfg.get("duckdb_path")

                if not duckdb_path:
                    if output_cfg.get("output_dir"):
                        duckdb_path = os.path.join(output_cfg["output_dir"], "metrics.duckdb")
                    else:
                        config_dir = os.path.dirname(args.config) or "."
                        duckdb_path = os.path.join(config_dir, "metrics.duckdb")

                if not os.path.exists(duckdb_path):
                    print(f"Error: DuckDB database not found at {duckdb_path}", file=sys.stderr)
                    print("Make sure to run the pipeline first or specify the correct database path", file=sys.stderr)
                    return 1

                output_dir = output_cfg.get("output_dir", ".")
                generate_all_reports(output_dir, duckdb_path, reports_cfg)

                print(f"Reports generated according to configuration in {output_dir}")
                return 0

            elif hasattr(args, 'database') and args.database:
                if not args.output:
                    print("Error: --output is required when using --database", file=sys.stderr)
                    return 1

                from text2sql_antipattern.output.report import generate_query_quality_report

                generate_query_quality_report(args.database, args.output)
                print(f"Query quality report generated: {args.output}")
                return 0
            else:
                print("Error: Either --config or --database must be specified", file=sys.stderr)
                return 1

        except ImportError:
            print("Error: duckdb not installed. Install with: pip install duckdb", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error generating report: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return 1

    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
