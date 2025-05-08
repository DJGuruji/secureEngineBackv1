import subprocess
import json
import logging
import tempfile
import os
from typing import List, Dict, Optional
from fastapi import HTTPException, status
import yaml

logger = logging.getLogger(__name__)

def run_semgrep(file_path: str, custom_rule: Optional[str] = None) -> List[Dict]:
    """Run semgrep on a file or directory and return results."""
    try:
        logger.info(f"Running semgrep on {file_path}")
        
        # Base command
        cmd = ["semgrep", "--json"]
        
        # Handle custom rule
        if custom_rule:
            try:
                # Validate JSON format
                rule_data = json.loads(custom_rule)
                if not isinstance(rule_data, dict) or "rules" not in rule_data:
                    raise ValueError("Invalid rule format: must contain 'rules' array")
                
                # Create temporary file for the rule
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_rule:
                    # Convert JSON to YAML format that Semgrep expects
                    yaml.dump(rule_data, temp_rule)
                    temp_rule_path = temp_rule.name
                
                # Add rule file to command
                cmd.extend(["--config", temp_rule_path])
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format in custom rule")
            except Exception as e:
                raise ValueError(f"Error processing custom rule: {str(e)}")
        else:
            # Use default auto config
            cmd.extend(["--config", "auto"])
        
        # Add target file
        cmd.append(file_path)
        
        # Run semgrep
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Clean up temporary rule file if it exists
        if custom_rule and 'temp_rule_path' in locals():
            try:
                os.unlink(temp_rule_path)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary rule file: {str(e)}")
        
        if result.returncode != 0:
            logger.error(f"Semgrep error:\n{result.stdout}\n{result.stderr}")
            raise Exception(f"Semgrep failed: {result.stderr}")
            
        # Parse results
        try:
            results = json.loads(result.stdout)
            return results.get("results", [])
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Semgrep output: {result.stdout}")
            raise Exception("Failed to parse Semgrep output")
            
    except Exception as e:
        logger.error(f"Error running semgrep: {str(e)}")
        raise 