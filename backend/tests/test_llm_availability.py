from types import SimpleNamespace

from app import llm_client


def test_offline_model_recovers_without_restart(monkeypatch):
    clock = [100.0]
    online = [False]
    calls = []

    def models():
        calls.append(True)
        if not online[0]:
            raise ConnectionError('offline')
        return SimpleNamespace(data=[SimpleNamespace(id=llm_client.settings.LLM_MODEL)])

    client = SimpleNamespace(models=SimpleNamespace(list=models))
    client.with_options = lambda **kwargs: client
    monkeypatch.setattr(llm_client, '_available', None)
    monkeypatch.setattr(llm_client, '_checked_at', 0)
    monkeypatch.setattr(llm_client, 'get_client', lambda: client)
    monkeypatch.setattr(llm_client.time, 'monotonic', lambda: clock[0])
    assert llm_client.is_available() is False
    online[0] = True
    assert llm_client.is_available() is False
    assert len(calls) == 1
    clock[0] += 6
    assert llm_client.is_available() is True


def test_running_server_without_configured_model_is_offline(monkeypatch):
    client = SimpleNamespace(models=SimpleNamespace(list=lambda: SimpleNamespace(data=[])))
    client.with_options = lambda **kwargs: client
    monkeypatch.setattr(llm_client, 'get_client', lambda: client)
    monkeypatch.setattr(llm_client, '_available', None)
    assert llm_client.is_available() is False
