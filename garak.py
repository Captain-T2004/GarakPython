import subprocess
import json
import re
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class GarakWrapper:
    def __init__(self, garak_path: str = "garak"):
        """
        Initialize the Garak wrapper
        
        Args:
            garak_path: Path to the Garak CLI tool (default: assumes 'garak' is in PATH)
        """
        self._garak_path = garak_path

    def strip_ansi_codes(self, text: str):
        """Remove ANSI color and formatting escape codes from text."""
        ansi_escape = re.compile(r'\x1b\[[0-9;]*[mz]')
        return ansi_escape.sub('', text)

    def parse_garak_probes(self, content: str):
        # Strip ANSI codes from content
        content = self.strip_ansi_codes(content)

        # Extract version and timestamp (if present)
        version_match = re.search(r'garak LLM vulnerability scanner (v[\d.]+)', content)
        timestamp_match = re.search(r'at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)', content)

        # Parse probes
        probe_lines = content.split('\n')[1:]  # Skip the first line with version info
        
        # Categorize probes
        probes_dict = {}
        
        for line in probe_lines:
            # Skip empty lines
            if not line.strip():
                continue
            
            # Extract probe details
            probe_match = re.match(r'probes: ([\w.]+)( \S+)?', line)
            if probe_match:
                probe_name = probe_match.group(1)
                status = probe_match.group(2).strip() if probe_match.group(2) else 'active'
                
                # Split the probe name into category and specific probe
                parts = probe_name.split('.')
                category = parts[0]
                specific_probe = '.'.join(parts[1:]) if len(parts) > 1 else None
                
                # Organize probes by category
                if category not in probes_dict:
                    probes_dict[category] = []
                
                # Add probe with its status
                probe_entry = {
                    'name': specific_probe or category,
                    'full_path': probe_name,
                    'status': status
                }
                probes_dict[category].append(probe_entry)

        # Prepare final JSON structure
        output_data = {
            'version': version_match.group(1) if version_match else None,
            'timestamp': timestamp_match.group(1) if timestamp_match else None,
            'probes': probes_dict
        }

        return json.dumps(output_data, sort_keys=False)

    def _run_command(self, 
                     subcommand: str, 
                     args: List[str] = []) -> Any:
        """
        Internal method to run Garak commands safely
        
        Args:
            subcommand: The Garak subcommand to run
            args: Additional arguments for the command
        
        Returns:
            Parsed command output
        
        Raises:
            GarakError for command execution failures
        """
        if(subcommand == ""):
            full_command = [self._garak_path] + args
        else:
            full_command = [
                self._garak_path, 
                subcommand
            ] + args
        print(full_command)
        try:
            # Execute the command
            result = subprocess.run(
                full_command, 
                capture_output=True, 
                text=True, 
                check=True
            )
            return result.stdout
            
            # Parse output based on format
            
        
        except subprocess.CalledProcessError as e:
            return f"Garak command failed: {e.stderr}"
        except json.JSONDecodeError:
            return "Failed to parse JSON output"
    
    def list_probes(self) -> List[Dict[str, Any]]:
        """
        List available probes in Garak
        
        Returns:
            List of available probes with their details
        """
        results = self._run_command("--list_probes")
        return self.parse_garak_probes(results)
    
    def run_probe(self, 
                  probe_list: List[str] = ["all"], 
                  model_type: Optional[str] = None,
                  model_name: Optional[str] = None,
                  report_name: Optional[str] = None,
                  additional_args: List[str] = []) -> Dict[str, Any]:
        """
        Run a specific Garak probe
        
        Args:
            probe_name: Name of the probe to run
            model: Optional model to test
            additional_args: Additional CLI arguments
        
        Returns:
            Probe results
        """
        # Construct command arguments
        args = []
        args.extend(["--model_type", model_type])
        args.extend(["--model_name", model_name])
        args.extend(["--probes", ",".join(probe_list)])
        args.extend(["--report_prefix", report_name])
        args.extend(additional_args)
        return self._run_command("", args)