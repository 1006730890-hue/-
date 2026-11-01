"""JianHeng adapter: authoritative root request, plan validation and field isolation."""
import json
import re
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from .. import config, tools, security, audit
from ..db import db
from ..branding import SECURITY_ID, SECURITY_NAME
from .detection import inspect_input, scan_arguments, detector
from .drift_runtime import (ToolSpec, ToolEffect, PlanStep, SecurePlan, ProposedCall,
                            SecurePlanner, DynamicValidator, InjectionIsolator, validate_arguments)
from .drift_llm import LLMDynamicValidator, PROMPTS

POLICY_VERSION = 'duplex-bank-1'
READ_TOOLS = frozenset(name for name, risk in security.TOOL_RISK.items() if risk == security.GREEN)
VERBS = {
    'schedule_transfer': ('预约',), 'create_aa_request': ('AA','aa','收款','分摊'),
    'transfer': ('转账','转给','转','汇款','付款'),
    'purchase_wealth': ('申购','买入','购买'), 'redeem_wealth': ('赎回','卖出'),
    'cancel_subscription': ('取消','关闭'), 'toggle_card_freeze': ('冻结','解冻','锁卡'),
    'report_card_loss': ('挂失',), 'adjust_credit_limit': ('调整','调高','调低','提高','降低'),
    'create_goal': ('创建','新建','设定','设置','提醒'),
}


def tool_specs():
    result = []
    for entry in tools.TOOL_SCHEMAS:
        fn = entry['function']
        schema = json.loads(json.dumps(fn['parameters']))
        schema['additionalProperties'] = False
        if fn['name'] == 'list_transactions':
            schema['properties']['limit'].update(minimum=1,maximum=200)
        if fn['name'] == 'monthly_bill':
            schema['properties']['year_month'].update(pattern=r'^\d{4}-(0[1-9]|1[0-2])$')
        for prop in schema.get('properties', {}).values():
            if prop.get('type') == 'string':
                prop.setdefault('maxLength', 2000)
        result.append(ToolSpec(fn['name'],fn['description'],schema,
                               tuple(schema.get('required', [])),fn['name'] not in READ_TOOLS,
                               VERBS.get(fn['name'], ())))
    return result


def _amounts(root):
    # Every monetary value in this root must agree; digits in names/phones are not amounts.
    values = re.findall(r'(?<![\d.])([+-]?\d+(?:\.\d+)?)(?:\s*)(万元|万|元|块|人民币)', root)
    return [Decimal(value) * (10000 if unit in ('万','万元') else 1) for value, unit in values]


def root_authorizes(root, name, args):
    """Conservative action/target binding, independent of model and tool results.

    Ambiguous, negated or quoted money instructions are clarified, not executed.
    Complex derived amounts require a new explicit request from the customer.
    """
    if name in READ_TOOLS:
        return True, ''
    if not any(verb in root for verb in VERBS.get(name, ())):
        return False, '当前用户请求未授权此业务操作'
    if re.search(r'不要|别(?:再|给|转|冻|买|执行)?|不(?:要|用|转|买|冻结)|取消转账|撤销|假如|假设|例如|举例|解释|为什么|怎么|如何|是否|能不能|[“”"「」『』]', root):
        return False, '请求包含否定、引用或询问，请明确要执行的操作'
    if name in ('transfer','purchase_wealth','redeem_wealth','adjust_credit_limit','schedule_transfer','create_aa_request'):
        values = _amounts(root)
        amount = args.get('new_limit') if name == 'adjust_credit_limit' else args.get('total_amount') if name == 'create_aa_request' else args.get('amount')
        if len(values) != 1 or amount is None or Decimal(str(amount)) != values[0]:
            return False, '请用一条明确指令指定唯一金额（元）'
    if name == 'schedule_transfer':
        with db() as conn:
            recipient = conn.execute('SELECT name,user_id FROM recipients WHERE id=?',(args.get('recipient_id'),)).fetchone()
        if not recipient or recipient['name'] not in root or args.get('execute_at','')[:10] not in root:
            return False, '请明确预约日期和已登记收款人'
    if name == 'create_aa_request':
        if not args.get('title') or args['title'] not in root or not re.search(str(args.get('participant_count'))+r'\s*人',root):
            return False, '请明确AA主题和参与人数'
    if name == 'transfer':
        recipient = args.get('to_name', '')
        if not recipient or recipient not in root or recipient in ('收款人','对方','他','她'):
            return False, '收款人须由当前用户明确指定'
        # Require a transfer clause next to the specified recipient; mention elsewhere is insufficient.
        escaped = re.escape(recipient)
        if not (re.search(r'(?:给|向|转给)\s*'+escaped+r'\s*(?:转账|转|汇款|付款)?\s*[0-9]', root)
                or re.search(r'(?:转账|转|汇款|付款)\s*给?\s*'+escaped+r'\s*[0-9]', root)):
            return False, '请明确收款人与转账金额的对应关系'
        if args.get('to_phone') and args['to_phone'] not in root:
            return False, '收款手机号未获授权'
        if args.get('note') and args['note'] not in root:
            return False, '转账备注未获授权'
    if name in ('purchase_wealth','redeem_wealth') and args.get('product_name','') not in root:
        return False, '产品名称未获当前请求授权'
    if name == 'cancel_subscription':
        requested = args.get('name','')
        if not requested or (requested not in root and not any(alias in root and alias in requested for alias in ('网易云','爱奇艺','健身房'))):
            return False, '请明确要取消的订阅'
    if name == 'toggle_card_freeze':
        unfreeze = '解冻' in root
        if args.get('action') != ('unfreeze' if unfreeze else 'freeze'):
            return False, '冻结与解冻操作不一致'
    if name in ('toggle_card_freeze','report_card_loss','adjust_credit_limit'):
        with db() as conn:
            row = conn.execute('SELECT * FROM cards WHERE id=?', (args.get('card_id'),)).fetchone()
        if not row:
            return False, '银行卡不存在'
        card_reference = row['card_type'] in root or str(row['card_no'])[-4:] in root or f"卡{row['id']}" in root
        if not card_reference:
            return False, '请指定卡片类型或尾号'
    if name == 'create_goal':
        if not args.get('description') or args['description'] not in root:
            return False, '目标内容须来自当前用户请求'
        for key in ('due_date','plan'):
            if args.get(key) and args[key] not in root:
                return False, '任务日期或计划未获明确授权'
    return True, ''


@dataclass
class TurnGuard:
    user_id: int
    root: str
    conversation_id: str = ''
    infer: object = None
    request_id: str = ''
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    completed: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    trajectory: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    plan: object = None

    def __post_init__(self):
        self.specs = tool_specs()
        self.registry = {s.name: s for s in self.specs}
        self.mode = 'llm' if self.infer else 'deterministic'
        if self.infer:
            callback = self.infer
            def traced(stage,payload):
                verdict = callback(stage,payload)
                self.record('model_verdict',{'purpose':stage,'output_preview':str(verdict)[:2000]})
                return verdict
            self.infer = traced
        self.validator = (LLMDynamicValidator(self.specs, self.infer, model_identity=config.settings.LLM_MODEL)
                          if self.infer else DynamicValidator(self.specs,
                          tool_permissions={name: ('READ' if name in READ_TOOLS else 'WRITE') for name in self.registry}))
        if self.infer:
            self.plan = SecurePlanner(self.specs,
                model_callback=lambda prompt: self.infer('plan', {'prompt': prompt}),
                repair_callback=lambda prompt: self.infer('plan', {'prompt': prompt})).create_plan(self.root)
        else:
            self.plan = SecurePlan(self.run_id, self.root, (), 'server_router')
        self.record('plan', {'plan': self.plan.to_dict(), 'mode': self.mode})

    def record(self, stage, detail):
        event = {'stage': stage, **detail}
        self.evidence.append(event)
        audit.log(self.user_id, 'duplex', stage, {'run_id': self.run_id, 'conversation_id': self.conversation_id}, event,
                  'red' if detail.get('decision') == 'deny' else 'green')

    def check(self, name, args, *, confirmed=False):
        if self.conversation_id and self.request_id:
            with db() as conn:
                current = conn.execute('SELECT active_request FROM conversations WHERE id=? AND user_id=?',(self.conversation_id,self.user_id)).fetchone()
            if not current or current['active_request'] != self.request_id:
                return self._deny('request_superseded','请求已被后续消息替代')
        spec = self.registry.get(name)
        if spec is None:
            return self._deny('unknown_tool', '工具未登记')
        if not isinstance(args, dict):
            return self._deny('invalid_arguments', '参数必须为对象')
        # Permit decimal strings at the application boundary, normalize before strict schema.
        args = dict(args)
        for key in ('amount','new_limit'):
            if key in args:
                try:
                    args[key] = tools.valid_amount(args[key])
                except tools.ToolError as exc:
                    return self._deny('invalid_amount', str(exc))
        errors = validate_arguments(spec, args)
        if errors:
            return self._deny('invalid_arguments', '；'.join(errors))
        ok, reason = root_authorizes(self.root, name, args)
        if not ok:
            return self._deny('authorization_required', reason)
        policy = security.decide(name, args, self.user_id)
        if not policy.allowed:
            return self._deny(policy.code, policy.reason)
        if name in ('toggle_card_freeze','report_card_loss','adjust_credit_limit'):
            with db() as conn:
                card = conn.execute('SELECT user_id FROM cards WHERE id=?', (args['card_id'],)).fetchone()
            if not card or card['user_id'] != self.user_id:
                return self._deny('account_scope_violation', '卡片不属于当前用户')
        scanned = scan_arguments(name, args, spec.description)
        if scanned['decision'] != 'allow':
            return self._deny(scanned.get('code','unsafe_arguments'), scanned.get('reason','参数扫描拒绝'))
        call = ProposedCall(name, args, completed_steps=tuple(self.completed), call_id=uuid.uuid4().hex)
        if not self.infer:
            # The deterministic route is application-owned, then checked by the copied runtime.
            step = PlanStep('step-'+str(len(self.plan.steps)+1), name, args, tuple(self.completed))
            self.plan = SecurePlan(self.plan.plan_id, self.root, self.plan.steps+(step,), 'server_router', self.plan.revision+1)
        decision = (self.validator.validate(self.plan, call, observations=self.observations, trajectory=self.trajectory)
                    if self.infer else self.validator.validate(self.plan, call))
        self.record('dynamic_validation', {'tool': name, 'arguments': args, **decision.to_dict()})
        if decision.decision == 'deny':
            return self._deny('plan_validation_failed', decision.reason)
        if decision.effective_plan:
            self.plan = decision.effective_plan
        if decision.matched_step_id:
            self._next_step = decision.matched_step_id
        return {'decision': 'ask' if name not in READ_TOOLS or decision.decision == 'ask' else 'allow',
                'risk': policy.risk, 'args': args, 'plan': self.plan.to_dict()}

    def _deny(self, code, reason):
        self.record('authorization', {'decision': 'deny', 'code': code, 'reason': reason})
        return {'decision': 'deny', 'code': code, 'reason': reason}

    def isolate(self, name, result):
        isolated = InjectionIsolator(detector).isolate(result, tool_name=name)
        self.record('result_isolation', {'tool': name, 'detected': isolated.detected,
            'quarantined': isolated.quarantined, 'digest': isolated.envelope.content_hash,
            'reasons': list(isolated.reasons)})
        if isolated.quarantined:
            safe = {'ok': False, 'error': '工具结果安全检测不可用或结果被隔离'}
        else:
            safe = json.loads(isolated.safe_content)
        self.observations.append({'tool_name': name, 'safe_result': safe, 'source': 'untrusted_tool_data'})
        self.trajectory.append({'tool_name': name})
        if getattr(self, '_next_step', None):
            self.completed.append(self._next_step)
        return safe

    def finish(self, response):
        with db() as conn:
            conn.execute('''INSERT INTO duplex_runs(id,user_id,conversation_id,root_instruction,mode,plan,evidence,created_at)
                            VALUES(?,?,?,?,?,?,?,datetime('now'))''',
                         (self.run_id,self.user_id,self.conversation_id,self.root,self.mode,
                          json.dumps(self.plan.to_dict(),ensure_ascii=False),json.dumps(self.evidence,ensure_ascii=False)))
        response['security'] = {'framework': SECURITY_ID, 'framework_name': SECURITY_NAME, 'run_id': self.run_id, 'mode': self.mode,
                                'decision': 'deny' if response.get('blocked') else ('ask' if response.get('needs_confirm') else 'allow'),
                                'policy_version': POLICY_VERSION}
        return response
