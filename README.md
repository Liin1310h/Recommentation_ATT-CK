# Traceable ATT&CK Technique Recommendation – D1 data source survey

Research project: recommend MITRE ATT&CK techniques for unlabeled security events via hybrid retrieval and a knowledge graph.
This repository currently holds only the week-1 deliverable D1 (survey of candidate data sources). No pipeline or results yet.

## Contents
- `docs/` – survey reports for three sources and the source-selection note.
- `scripts/` – read-only survey scripts (Python 3, PyYAML for the YAML-based surveys).
- `data/evtx_manifest.sha256` – SHA256 of the EVTX files that were surveyed.
- `data/splunk_sample_paths.txt` – paths of the 30-file Splunk sample used in the survey.

## Raw data is not included
The logs are third-party data and are not redistributed here. Fetch them yourself at the commits that were surveyed:

| Source | Commit surveyed | License |
|---|---|---|
| [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | `4ceed2f4706daf601c212a8f91c113dd85349a2c` | GPL v3 |
| [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` | MIT |
| [splunk/attack_data](https://github.com/splunk/attack_data) | `3a25034e7446cbdd108b87e848d5296530545c80` | Apache 2.0 |

These datasets contain attack telemetry; some files are flagged by antivirus software (Windows Defender blocked parts of `splunk/attack_data`). Handle them on a machine where that is permitted.

## Limits
- Survey numbers are metadata- or sample-level; unmeasured items are listed in each report under "Chưa kiểm chứng".
- Reports are written in Vietnamese.
- A single annotator; label sources are the datasets' own metadata, not independent ground truth.
- This repository has no license file yet; all rights reserved until one is added.
