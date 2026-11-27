"""Candidate QLoRA workflow. Not GPU-validated; no training is run without --execute.

Uses reviewed feature records and local HF weights, never malware binaries or network uploads.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from training.validate_dataset import load_and_validate

ROOT=Path(__file__).resolve().parents[1]


def write(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def inventory(directory):
    result=[]
    for path in sorted(directory.rglob('*')):
        if path.is_file() and path.suffix in ('.json','.safetensors','.model','.txt'):
            with path.open('rb') as stream:
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            result.append({'file':path.relative_to(directory).as_posix(),'bytes':path.stat().st_size,'sha256':digest})
    return result


def encode_record(row,tokenizer,max_length):
    prefix=tokenizer.apply_chat_template(row['prompt_messages'],tokenize=True,add_generation_prompt=True)
    full=tokenizer.apply_chat_template(row['prompt_messages']+[{
        'role':'assistant','content':json.dumps(row['completion'],ensure_ascii=False)}],
        tokenize=True,add_generation_prompt=False)
    if full[:len(prefix)]!=prefix or len(full)<=len(prefix):
        raise ValueError('Chat template does not align response-only labels')
    if len(full)>max_length:
        raise ValueError('Record exceeds sequence budget; curate it instead of silently truncating evidence/labels')
    return {'input_ids':full,'attention_mask':[1]*len(full),
            'labels':[-100]*len(prefix)+full[len(prefix):]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,required=True)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate-only',action='store_true')
    mode.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    config=json.loads(args.config.read_text(encoding='utf-8'))
    try:
        splits,validation=load_and_validate(ROOT/config['data_dir'])
    except Exception as exc:
        print(json.dumps({'status':'data_not_ready','training_performed':False,'reason':str(exc)}))
        return 2
    if args.validate_only:
        print(json.dumps({'training_performed':False,'dataset_validation':validation}))
        return 0
    base=(ROOT/config['base_model_local_dir']).resolve()
    if not (base/'config.json').is_file() or not list(base.glob('*.safetensors')):
        raise ValueError('Local HF Safetensors base missing; Ollama GGUF is not the training checkpoint')
    provenance=base/'UPSTREAM_PROVENANCE.json'
    if not provenance.is_file():
        raise ValueError('Record model_id and exact upstream revision in UPSTREAM_PROVENANCE.json first')
    origin=json.loads(provenance.read_text())
    if origin.get('model_id')!=config['base_model_id'] or not origin.get('revision'):
        raise ValueError('Base provenance mismatch')
    os.environ['HF_HUB_OFFLINE']='1'
    os.environ['TRANSFORMERS_OFFLINE']='1'
    os.environ['HF_HUB_DISABLE_TELEMETRY']='1'
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8]
    output=(ROOT/config['output_root']/stamp).resolve()
    output.mkdir(parents=True,exist_ok=False)
    receipt={'run_id':stamp,'started_at':datetime.now(timezone.utc).isoformat(),
             'status':'started','optimizer_steps_completed':0,'training_claim':'candidate run; inspect status/artifacts'}
    write(output/'config.json',config)
    write(output/'dataset-validation.json',validation)
    write(output/'base-inventory.json',{'origin':origin,'files':inventory(base)})
    write(output/'run-receipt.json',receipt)
    trainer=None
    try:
        import torch
        from transformers import AutoModelForCausalLM,AutoTokenizer,BitsAndBytesConfig,Trainer,TrainingArguments,set_seed
        from peft import LoraConfig,get_peft_model,prepare_model_for_kbit_training
        if not torch.cuda.is_available():
            raise RuntimeError('CUDA GPU required by this candidate; CPU fallback is not silently enabled')
        set_seed(config['seed'])
        (output/'pip-freeze.txt').write_text(subprocess.check_output([sys.executable,'-m','pip','freeze'],text=True))
        write(output/'environment.json',{'python':sys.version,'platform':platform.platform(),
             'torch':torch.__version__,'cuda':torch.version.cuda,'gpu':torch.cuda.get_device_name(0),
             'gpu_total_bytes':torch.cuda.get_device_properties(0).total_memory})
        tokenizer=AutoTokenizer.from_pretrained(base,local_files_only=True,trust_remote_code=False)
        if tokenizer.pad_token_id is None:
            tokenizer.pad_token=tokenizer.eos_token
        model=AutoModelForCausalLM.from_pretrained(base,local_files_only=True,trust_remote_code=False,
            device_map={'':0},torch_dtype=torch.float16,quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,bnb_4bit_quant_type='nf4',bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16))
        model=prepare_model_for_kbit_training(model)
        model.config.use_cache=False
        model=get_peft_model(model,LoraConfig(task_type='CAUSAL_LM',r=config['lora_r'],
            lora_alpha=config['lora_alpha'],lora_dropout=config['lora_dropout'],
            target_modules=config['target_modules'],bias='none'))
        class Records(torch.utils.data.Dataset):
            def __init__(self,rows):
                self.rows=[encode_record(r,tokenizer,config['max_seq_length']) for r in rows]
            def __len__(self):
                return len(self.rows)
            def __getitem__(self,index):
                return self.rows[index]
        def collate(rows):
            length=max(len(r['input_ids']) for r in rows)
            return {key:torch.tensor([r[key]+[pad]*(length-len(r[key])) for r in rows],dtype=torch.long)
                    for key,pad in (('input_ids',tokenizer.pad_token_id),('attention_mask',0),('labels',-100))}
        arguments=TrainingArguments(output_dir=str(output/'checkpoints'),
            num_train_epochs=config['epochs'],learning_rate=config['learning_rate'],
            per_device_train_batch_size=config['per_device_train_batch_size'],
            per_device_eval_batch_size=1,gradient_accumulation_steps=config['gradient_accumulation_steps'],
            gradient_checkpointing=True,fp16=True,logging_steps=config['logging_steps'],
            eval_strategy='epoch',save_strategy='epoch',report_to='none',push_to_hub=False,
            seed=config['seed'],data_seed=config['seed'])
        trainer=Trainer(model=model,args=arguments,train_dataset=Records(splits['train']),
            eval_dataset=Records(splits['validation']),data_collator=collate,processing_class=tokenizer)
        result=trainer.train()
        trainer.save_state()
        model.save_pretrained(output/'adapter',safe_serialization=True)
        tokenizer.save_pretrained(output/'adapter')
        write(output/'loss-history.json',trainer.state.log_history)
        write(output/'checkpoint-hashes.json',inventory(output/'adapter'))
        receipt.update(status='completed',optimizer_steps_completed=trainer.state.global_step,
                       train_metrics=result.metrics,max_memory_allocated_bytes=torch.cuda.max_memory_allocated(),
                       test_evaluation_performed=False,coursework_quality_accepted=False)
    except Exception as exc:
        receipt.update(status='failed',error=type(exc).__name__+': '+str(exc))
        if trainer is not None:
            receipt['optimizer_steps_completed']=trainer.state.global_step
            write(output/'loss-history.json',trainer.state.log_history)
        raise
    finally:
        receipt['finished_at']=datetime.now(timezone.utc).isoformat()
        write(output/'run-receipt.json',receipt)
    print(json.dumps({'run_id':stamp,'status':receipt['status'],'output':str(output)}))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
