#!/usr/bin/env python3
"""
Experiment directory manager for organizing multiple experiment runs
"""

import os
import json
from pathlib import Path
from datetime import datetime

class ExperimentManager:
    """Manages experiment directories and metadata"""
    
    def __init__(self, base_dir="experiments"):
        """
        Initialize experiment manager
        
        Args:
            base_dir: Base directory for all experiments (relative to gadget_analysis/)
        """
        self.gadget_analysis_dir = Path(__file__).parent
        self.base_dir = self.gadget_analysis_dir / base_dir
        self.base_dir.mkdir(exist_ok=True)
        
        # Index file for tracking experiments
        self.index_file = self.base_dir / "experiment_index.json"
        self.experiments = self._load_index()
    
    def _load_index(self):
        """Load experiment index from disk"""
        if self.index_file.exists():
            with open(self.index_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_index(self):
        """Save experiment index to disk"""
        with open(self.index_file, 'w') as f:
            json.dump(self.experiments, f, indent=2)
    
    def create_experiment(self, name=None, description="", config=None):
        """
        Create a new experiment directory
        
        Args:
            name: Optional name for the experiment (auto-generated if None)
            description: Description of the experiment
            config: Dictionary of configuration parameters
        
        Returns:
            Path: Path to the new experiment directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if name:
            exp_id = f"{timestamp}_{name}"
        else:
            exp_id = timestamp
        
        exp_dir = self.base_dir / exp_id
        exp_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (exp_dir / "captures").mkdir(exist_ok=True)
        (exp_dir / "results").mkdir(exist_ok=True)
        (exp_dir / "logs").mkdir(exist_ok=True)
        
        # Save metadata
        metadata = {
            "experiment_id": exp_id,
            "timestamp": timestamp,
            "name": name or "unnamed",
            "description": description,
            "config": config or {},
            "created_at": datetime.now().isoformat(),
            "status": "created",
            "scenarios_completed": []
        }
        
        with open(exp_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Update index
        self.experiments[exp_id] = {
            "path": str(exp_dir),
            "name": name or "unnamed",
            "created_at": metadata["created_at"],
            "status": "created"
        }
        self._save_index()
        
        print(f"[+] Created experiment: {exp_id}")
        print(f"    Path: {exp_dir}")
        
        return exp_dir
    
    def get_experiment(self, exp_id):
        """Get experiment directory by ID"""
        if exp_id in self.experiments:
            return Path(self.experiments[exp_id]["path"])
        return None
    
    def get_latest_experiment(self):
        """Get the most recently created experiment"""
        if not self.experiments:
            return None
        
        latest_id = max(self.experiments.keys(), 
                       key=lambda k: self.experiments[k]["created_at"])
        return Path(self.experiments[latest_id]["path"])
    
    def list_experiments(self, limit=10):
        """List recent experiments"""
        sorted_exps = sorted(
            self.experiments.items(),
            key=lambda x: x[1]["created_at"],
            reverse=True
        )
        
        print(f"\n{'='*70}")
        print(f"Recent Experiments (showing {min(limit, len(sorted_exps))} of {len(sorted_exps)})")
        print(f"{'='*70}")
        
        for exp_id, info in sorted_exps[:limit]:
            exp_path = Path(info["path"])
            metadata_file = exp_path / "metadata.json"
            
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                print(f"\n[{exp_id}]")
                print(f"  Name: {info['name']}")
                print(f"  Status: {metadata.get('status', 'unknown')}")
                print(f"  Created: {info['created_at']}")
                print(f"  Path: {exp_path}")
                
                if metadata.get('scenarios_completed'):
                    print(f"  Completed: {', '.join(metadata['scenarios_completed'])}")
    
    def update_status(self, exp_id, status, scenarios_completed=None):
        """Update experiment status"""
        exp_path = self.get_experiment(exp_id)
        if not exp_path:
            return False
        
        metadata_file = exp_path / "metadata.json"
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        metadata["status"] = status
        metadata["updated_at"] = datetime.now().isoformat()
        
        if scenarios_completed:
            metadata["scenarios_completed"] = scenarios_completed
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Update index
        self.experiments[exp_id]["status"] = status
        self._save_index()
        
        return True
    
    def cleanup_old_experiments(self, keep_recent=5):
        """Remove old experiment directories (keep only recent N)"""
        sorted_exps = sorted(
            self.experiments.items(),
            key=lambda x: x[1]["created_at"],
            reverse=True
        )
        
        to_remove = sorted_exps[keep_recent:]
        
        for exp_id, info in to_remove:
            exp_path = Path(info["path"])
            if exp_path.exists():
                import shutil
                shutil.rmtree(exp_path)
                print(f"[+] Removed old experiment: {exp_id}")
            
            del self.experiments[exp_id]
        
        self._save_index()
        print(f"[+] Cleaned up {len(to_remove)} old experiments")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage gadget analysis experiments")
    parser.add_argument("--create", action="store_true", help="Create a new experiment")
    parser.add_argument("--name", help="Experiment name")
    parser.add_argument("--description", default="", help="Experiment description")
    parser.add_argument("--list", action="store_true", help="List experiments")
    parser.add_argument("--cleanup", type=int, metavar="N", help="Keep only N recent experiments")
    
    args = parser.parse_args()
    
    manager = ExperimentManager()
    
    if args.create:
        exp_dir = manager.create_experiment(
            name=args.name,
            description=args.description
        )
    elif args.list:
        manager.list_experiments()
    elif args.cleanup:
        manager.cleanup_old_experiments(keep_recent=args.cleanup)
    else:
        parser.print_help()
