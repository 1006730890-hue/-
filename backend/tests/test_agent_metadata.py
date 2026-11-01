"""Model formatting repairs preserve the validator's fail-closed behavior."""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import agent
from app.duplex.drift_llm import LLMDynamicValidator
from app.duplex.drift_runtime import ToolSpec, SecurePlan, PlanStep, ProposedCall


def _validate_with_model(monkeypatch, privilege_outputs):
    outputs = iter(privilege_outputs)
    classification_messages = []

    def infer(messages):
        if '工具权限分类器' in messages[1]['content']:
            classification_messages.append([dict(item) for item in messages])
            return next(outputs)
        assert '参数 checklist 格式化器' in messages[1]['content']
        return json.dumps({'name':'get_balance','required parameters':None,
                           'conditions':None,'reason':'原计划没有参数约束'})

    monkeypatch.setattr(agent.llm_client,'json_chat',infer)
    spec = ToolSpec('get_balance','读取账户余额',{'type':'object','properties':{},'additionalProperties':False})
    validator = LLMDynamicValidator([spec],agent._infer,model_identity='stub',cache={})
    plan = SecurePlan('test-plan','查看余额',(PlanStep('s1','get_balance',{}),))
    verdict = validator.validate(plan,ProposedCall('get_balance',{}))
    return verdict, classification_messages


def test_malformed_privilege_can_be_recovered_with_schema_feedback(monkeypatch):
    verdict, messages = _validate_with_model(monkeypatch,[
        '{}',json.dumps({'permission':'READ','reason':'此工具只读取余额'})])
    assert verdict.decision == 'allow'
    assert len(messages) == 2
    feedback = json.loads(messages[1][-1]['content'].removesuffix('\n/no_think'))
    assert feedback['required_schema']['required'] == ['permission','reason']
    assert feedback['required_schema']['additionalProperties'] is False
    assert 'permission' in feedback['format_error']
    assert verdict.evidence['privilege']['reason'] == '此工具只读取余额'


@pytest.mark.parametrize('invalid',[
    '{}','not JSON','{"permission":"ALLOW","reason":"invalid permission"}',
    '{"permission":"READ","reason":" "}',
    '{"permission":"READ","reason":"read only","extra":true}',
])
def test_persistent_bad_metadata_denies_without_static_fallback(monkeypatch,invalid):
    verdict, messages = _validate_with_model(monkeypatch,[invalid,invalid])
    assert verdict.decision == 'deny'
    assert len(messages) == 2
    assert 'required LLM validation failed' in verdict.reason
    assert 'privilege' not in verdict.evidence


def test_valid_write_classification_is_not_downgraded(monkeypatch):
    verdict, messages = _validate_with_model(monkeypatch,[
        '{"permission":"WRITE","reason":"此工具会修改状态"}'])
    assert verdict.decision == 'ask'
    assert len(messages) == 1
    assert verdict.evidence['privilege']['permission'] == 'WRITE'


def test_server_date_is_in_both_model_system_prompts(monkeypatch):
    class ServerDate(datetime):
        @classmethod
        def now(cls):
            return cls(2031,4,15,10,0,tzinfo=timezone.utc)

    monkeypatch.setattr(agent,'datetime',ServerDate)
    prompts = []

    def infer(messages):
        prompts.append(messages[0]['content'])
        return '{}'

    monkeypatch.setattr(agent.llm_client,'json_chat',infer)
    agent._infer('plan',{'prompt':'查看本月账单'})
    from app.duplex import memory
    monkeypatch.setattr(memory,'recall',lambda *args:[])

    def chat(messages,**kwargs):
        prompts.append(messages[0]['content'])
        return SimpleNamespace(content='请继续',tool_calls=[],model_dump=lambda **kwargs:{'role':'assistant','content':'请继续'})

    monkeypatch.setattr(agent.llm_client,'chat',chat)
    agent._run_with_llm(1,'查看本月账单',[],SimpleNamespace(conversation_id='',observations=[]))
    assert len(prompts) == 2
    for prompt in prompts:
        assert '2031-04-15' in prompt
        assert '当前月份：2031-04' in prompt
        assert '省略该参数并使用工具默认' in prompt


def _monthly_plan(*, self_reference=False):
    step = {'id':'step-1','tool':'monthly_bill','arguments':{'year_month':'2026-10'},
            'argument_sources':{},'depends_on':[]}
    if self_reference:
        step['argument_sources']['year_month'] = {'step_id':'step-1','path':['year_month'],'mode':'copy'}
    return {'steps':[step]}


def _stub_monthly_turn(monkeypatch, plans):
    plans = iter(plans)
    prompts, executed = [], []
    original = agent.TOOLS['monthly_bill']

    def infer(stage,payload):
        if stage == 'plan':
            assert not executed, 'no tool may execute before a valid plan exists'
            prompts.append(payload['prompt'])
            return next(plans)
        if stage == 'privilege_classification':
            return {'permission':'READ','reason':'only reads the bill'}
        if stage == 'parameter_constraints':
            return {**payload['initial_checklist'],'reason':'retain the original checklist'}
        raise AssertionError(stage)

    def monthly(user_id,args):
        executed.append((user_id,dict(args)))
        return original(user_id,args)

    def chat(messages,**kwargs):
        calls = [] if executed else [SimpleNamespace(id='stub-call',function=SimpleNamespace(
            name='monthly_bill',arguments='{"year_month":"2026-10"}'))]
        return SimpleNamespace(content='账单查询完成',tool_calls=calls,
            model_dump=lambda **kwargs:{'role':'assistant','content':'账单查询完成'})

    monkeypatch.setattr(agent,'_infer',infer)
    monkeypatch.setattr(agent.llm_client,'is_available',lambda:True)
    monkeypatch.setattr(agent.llm_client,'chat',chat)
    monkeypatch.setitem(agent.TOOLS,'monthly_bill',monthly)
    monkeypatch.setattr(agent,'_run_fallback',lambda *args:pytest.fail('online planning cannot use a fallback'))
    return prompts, executed


def test_self_referencing_plan_is_replanned_before_real_bill_read(app_modules,monkeypatch):
    prompts, executed = _stub_monthly_turn(monkeypatch,[
        _monthly_plan(self_reference=True),_monthly_plan()])
    result = agent.run(1,'查看2026年10月账单',[])
    assert not result.get('blocked'), result
    assert result['result']['year_month'] == '2026-10'
    assert executed == [(1,{'year_month':'2026-10'})]
    assert len(prompts) == 2
    assert prompts[1].startswith(prompts[0])
    assert 'VALIDATION_ERROR=' in prompts[1]
    assert 'unknown or forward dependencies' in prompts[1]
    with app_modules['db'].db() as conn:
        plan = json.loads(conn.execute('SELECT plan FROM duplex_runs').fetchone()['plan'])
    assert plan['source'] == 'model_repair'
    assert plan['steps'][0]['argument_sources'] == {}


@pytest.mark.parametrize('repair',[
    _monthly_plan(self_reference=True),
    {'steps':[{'id':'s1','tool':'unregistered_tool','arguments':{}}]},
    {'steps':[{'id':'s1','tool':'monthly_bill','arguments':{'year_month':'2026-99'}}]},
])
def test_bad_repair_still_blocks_before_any_business_tool(app_modules,monkeypatch,repair):
    prompts, executed = _stub_monthly_turn(monkeypatch,[
        _monthly_plan(self_reference=True),repair])
    result = agent.run(1,'查看2026年10月账单',[])
    assert result['blocked']
    assert result['code'] == 'security_validation_failed'
    assert result['executed'] is False
    assert len(prompts) == 2
    assert executed == []
    with app_modules['db'].db() as conn:
        assert conn.execute('SELECT COUNT(*) FROM pending_actions').fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE actor='tool'").fetchone()[0] == 0
