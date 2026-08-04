.PHONY: provision ingest analyze test clean

provision:
	cd sensor-infrastructure && ansible-playbook site.yml --ask-become-pass

ingest:
	python3 analysis-pipeline/run_pipeline.py raw-export/honeypot-replay.jsonl

analyze: ingest

test:
	python3 -m pytest tests/ --ignore=tests/test_reproducibility.py -v --junitxml=tests/pytest-report.xml
	python3 tests/test_sessionize.py tests/fixtures/public-fixtures.json
	python3 tests/test_reproducibility.py /home/yallbeslayin/soc-stage6/raw-export/honeypot-replay.jsonl

clean:
	rm -f clusters.json hash-ledger.csv hash-summary.json stix-bundle.json sessions.parquet sessions.json quarantine-log.json
	rm -rf detections/*
