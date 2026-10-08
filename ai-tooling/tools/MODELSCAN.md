# ModelScan

> In one minute: ModelScan is an open source command-line scanner that checks machine learning model files for unsafe code before you load them. It targets model serialization attacks, where a file such as a pickled PyTorch model runs attacker code the moment it is loaded. ML engineers and security teams use it as a gate in model download, training, and deployment pipelines.

| | |
|---|---|
| Category | Model scanning |
| Maintainer | Protect AI, which Palo Alto Networks acquired in July 2025; the repository stays under the `protectai` GitHub organization |
| License / access | Open source (Apache-2.0) |
| Official docs | [README on GitHub](https://github.com/protectai/modelscan) (no separate docs site; the old `modelscan.ai` address did not resolve when checked) |
| Repository | [protectai/modelscan](https://github.com/protectai/modelscan) |
| Checked | 8 Oct 2026, v0.8.8 (GitHub release and PyPI `modelscan`, 18 Feb 2026; the last release and last commit on `main`) |

## What it is for

- Scanning a model downloaded from a public hub before anyone loads it in a notebook or training job.
- Checking newly trained models for signs of a supply chain compromise before they are stored or shared.
- Re-scanning models right before deployment to an endpoint, in case stored files were tampered with.
- Failing a CI/CD job automatically when a model file contains dangerous operators.
- Writing JSON scan reports for tracking, or calling the scanner from Python on a file or directory.

## Quick start

1. Install ModelScan (PyPI metadata lists Python 3.10 to 3.12).

   ```bash
   pip install modelscan
   ```

   TensorFlow and HDF5 scanners need extras:

   ```bash
   pip install 'modelscan[ tensorflow, h5py ]'
   ```

2. Scan a model file or directory. Do this before loading it with any ML framework.

   ```bash
   modelscan -p /path/to/model_file.pkl
   ```

3. Write a JSON report for a pipeline.

   ```bash
   modelscan -p /path/to/model_file.pkl -r json -o scan_results.json
   ```

4. Use the exit code as a gate: `0` no issues found, `1` issues found, `2` scan error, `3` no supported files, `4` usage error.

5. Optional: create a settings file to customize the scan, then pass it with `--settings-file`.

   ```bash
   modelscan create-settings-file
   ```

## Key concepts

- **Model serialization attack**: Malicious code added to a model file when it is saved. It runs when the file is loaded, for example with `torch.load()` on a pickle-based file.
- **Static scanning**: ModelScan reads the file contents as bytes and looks for unsafe code signatures. It never loads the model, so scanning does not trigger the payload.
- **Supported formats**: Pickle and its variants (cloudpickle, dill, joblib), PyTorch pickle files, TensorFlow SavedModel, Keras H5, and Keras V3.
- **Severity levels**: CRITICAL (operators that can execute code, such as `exec`, `eval`, `os`, `subprocess`), HIGH (unsafe but not code-executing, such as network or file read and write operators), MEDIUM (operators the framework does not support or ModelScan does not recognize, including Keras Lambda layers), and LOW (currently unused).
- **Skipped files**: Files in unsupported formats are skipped. Use `--show-skipped` to list them so nothing passes unnoticed.
- **Python API**: `ModelScan(settings=DEFAULT_SETTINGS).scan(path)` runs the same scan from code.

## Security notes

- Treat every third-party model as untrusted code. Scan it in a disposable environment before it touches systems with cloud credentials or data access.
- A clean scan is not proof of safety. ModelScan matches known unsafe operators in supported formats; unsupported formats are skipped, and new evasion techniques appear over time.
- Prefer weight formats that do not execute code on load, and load pickle files only from sources you trust. Hugging Face's pickle security guide explains the risk and its own Hub scanning.
- Scan at three points: before using a pre-trained model, after training, and before deployment.
- The last release (v0.8.8) and the last commit on `main` date from February 2026. Check that the formats you depend on are covered, and consider pairing it with other scanners.
- If an issue is found, contact the model author and do not load the file. Some flagged code is a convenience shortcut, but it still opens an attack path.
- Model supply chain attacks are covered in the [AI Security Reference](/AI_SECURITY_REFERENCE.md), [AI Offensive Security Reference](/AI_OFFENSIVE_SECURITY_REFERENCE.md), [MITRE ATLAS Reference](/ATLAS_REFERENCE.md), and the [AI Threats 2026 case study](/case-studies/AI_THREATS_2026.md).

## Learn more

- [ModelScan README](https://github.com/protectai/modelscan)
- [Model serialization attacks explained](https://github.com/protectai/modelscan/blob/main/docs/model_serialization_attacks.md)
- [Severity levels](https://github.com/protectai/modelscan/blob/main/docs/severity_levels.md)
- [Example attack notebooks](https://github.com/protectai/modelscan/tree/main/notebooks)
- [Hugging Face: pickle scanning and safer formats](https://huggingface.co/docs/hub/security-pickle)
- [Palo Alto Networks completes acquisition of Protect AI](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai)
