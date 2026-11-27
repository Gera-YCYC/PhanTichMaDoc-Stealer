from stealer_agent.engine import Agent
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient


def test_low_ram_stops_before_inference_and_unloads(tmp_path,monkeypatch):
    class Model:
        unloaded=False
        def inspect(self): return {'tag':'fixture','details':{}}
        def chat(self,*args,**kwargs): raise AssertionError('Must not call inference at critical RAM')
        def unload(self): self.unloaded=True
        def vram_bytes(self): return None
    class Tools:
        def inspect(self): return {'tools':{'identify':{'available':True},'strings':{'available':True}}}
    monkeypatch.setattr('stealer_agent.engine.available_memory_bytes',lambda:15*1024*1024)
    model=Model()
    result=Agent({'model':'fixture','output_dir':str(tmp_path)},model,Tools()).run('fixture.txt')
    assert result['status']=='incomplete' and result['metrics']['model_calls']==0
    assert model.unloaded and 'ResourceBudgetExceeded' in result['analysis']['limitations'][0]


def test_think_is_opt_in_boolean_transport_option():
    captured=[]
    client=OllamaClient({'model':'fixture','ollama_url':'http://127.0.0.1:11435','think':False})
    client.http.request=lambda path,payload:captured.append(payload) or {'message':{'content':'{}'}}
    client.chat([],{})
    assert captured[0]['think'] is False
    del client.config['think']
    client.chat([],{})
    assert 'think' not in captured[1]


def test_available_memory_measurement_is_nullable_or_positive():
    value=available_memory_bytes()
    assert value is None or type(value) is int and value>0
