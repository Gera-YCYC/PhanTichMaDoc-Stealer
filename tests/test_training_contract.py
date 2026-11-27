"""Synthetic records test data guards only. These are never a training corpus."""
from copy import deepcopy
import pytest
from training.validate_dataset import validate_records
from training.train_lora import encode_record


def record(letter):
    return {'id':letter,'sample_sha256':letter*64,'family_id':'group-'+letter,
            'source_evidence':[{'artifact_sha256':'f'*64,'line_start':1,'line_end':3}],
            'prompt_messages':[{'role':'user','content':'Feature record '+letter}],
            'completion':{'action':'identify','arguments':{'sample':letter+'.bin'},'reason':'Identify format','report':None},
            'review':{'approved':True,'redacted':True,'synthetic':False,'reviewers':['reviewer-1','reviewer-2']}}


def splits():
    return {'train':[record('a')],'validation':[record('b')],'test':[record('c')]}


def test_family_leakage_rejected_even_with_distinct_hash():
    data=splits()
    data['test'][0]['family_id']=data['train'][0]['family_id']
    with pytest.raises(ValueError,match='family'):
        validate_records(data)


def test_prompt_leakage_rejected():
    data=splits()
    data['test'][0]['prompt_messages']=deepcopy(data['train'][0]['prompt_messages'])
    with pytest.raises(ValueError,match='prompt'):
        validate_records(data)


def test_unreviewed_or_synthetic_training_record_rejected():
    for field,value in (('approved',False),('synthetic',True),('reviewers',['one'])):
        data=splits()
        data['train'][0]['review'][field]=value
        with pytest.raises(ValueError,match='reviewers'):
            validate_records(data)


def test_empty_test_split_is_not_accepted():
    data=splits()
    data['test']=[]
    with pytest.raises(ValueError,match='nonempty'):
        validate_records(data)


def test_response_only_mask_and_overlength_rejection():
    class Tokenizer:
        def apply_chat_template(self,messages,**kwargs):
            return [10,20] if kwargs['add_generation_prompt'] else [10,20,30,40]
    encoded=encode_record(record('a'),Tokenizer(),4)
    assert encoded['labels']==[-100,-100,30,40]
    with pytest.raises(ValueError,match='sequence budget'):
        encode_record(record('a'),Tokenizer(),3)
