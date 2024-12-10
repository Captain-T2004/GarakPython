import subprocess
import json
import re
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class GarakWrapper:
    def __init__(self, garak_path: str = "garak"):
        self._garak_path = garak_path

    def strip_ansi_codes(self, text: str):
        ansi_escape = re.compile(r'\x1b\[[0-9;]*[mz]')
        return ansi_escape.sub('', text)

    def parse_garak_probes(self, content: str):
        content = self.strip_ansi_codes(content)
        version_match = re.search(r'garak LLM vulnerability scanner (v[\d.]+)', content)
        timestamp_match = re.search(r'at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)', content)
        probe_lines = content.split('\n')[1:]
        probes_dict = {}
        
        for line in probe_lines:
            if not line.strip():
                continue
            probe_match = re.match(r'probes: ([\w.]+)( \S+)?', line)
            if probe_match:
                probe_name = probe_match.group(1)
                status = probe_match.group(2).strip() if probe_match.group(2) else 'active'
                parts = probe_name.split('.')
                category = parts[0]
                specific_probe = '.'.join(parts[1:]) if len(parts) > 1 else None
                if category not in probes_dict:
                    probes_dict[category] = []

                probe_entry = {
                    'name': specific_probe or category,
                    'full_path': probe_name,
                    'status': status
                }
                probes_dict[category].append(probe_entry)

        output_data = {
            'version': version_match.group(1) if version_match else None,
            'timestamp': timestamp_match.group(1) if timestamp_match else None,
            'probes': probes_dict
        }

        return json.dumps(output_data, sort_keys=False)

    def _run_command(self, subcommand: str, args: List[str] = []) -> Any:
        if(subcommand == ""):
            full_command = [self._garak_path] + args
        else:
            full_command = [
                self._garak_path, 
                subcommand
            ] + args
        print(full_command)
        try:
            result = subprocess.run(
                full_command, 
                capture_output=True, 
                text=True, 
                check=True
            )
            print(result.stdout)
            return result.stdout
        
        except subprocess.CalledProcessError as e:
            print(e)
            return f"Garak command failed: {e.stderr}"
        except json.JSONDecodeError:
            print(e)
            return "Failed to parse JSON output"
    
    def list_probes(self) -> List[Dict[str, Any]]:
        results = self._run_command("--list_probes")
        return self.parse_garak_probes(results)
    
    def run_probe(self, 
                  probe_list: List[str] = ["all"], 
                  model_type: Optional[str] = None,
                  model_name: Optional[str] = None,
                  report_name: Optional[str] = None,
                  additional_args: List[str] = []) -> Dict[str, Any]:
        args = []
        args.extend(["--model_type", model_type])
        args.extend(["--model_name", model_name])
        args.extend(["--probes", ",".join(probe_list)])
        args.extend(["--report_prefix", report_name])
        args.extend(additional_args)
        return self._run_command("", args)