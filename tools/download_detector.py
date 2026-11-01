"""Download the authorized detector model into this checkout."""
import argparse
from pathlib import Path
from huggingface_hub import snapshot_download

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--model-root',type=Path,default=ROOT/'models')
args=parser.parse_args()
target=args.model_root/'meta-llama--Llama-Prompt-Guard-2-86M'
snapshot_download(repo_id='meta-llama/Llama-Prompt-Guard-2-86M',local_dir=target,
                  allow_patterns=['*.json','*.safetensors','*.model','*.txt','LICENSE*','USE_POLICY*'])
print(f'Model ready: {target}')
