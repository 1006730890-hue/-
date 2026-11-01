"""Evaluate bounded arithmetic over user numbers and actual safe tool facts."""
import json
import re
from decimal import Decimal, InvalidOperation


def evaluate_money_facts(facts, **context):
    if facts.get('kind') == 'shared_cost_refund':
        expression={'op':'subtract','left':{'source':'transaction_amount','transaction_id':facts.get('paid_transaction_id')},
            'right':{'op':'divide','left':{'source':'user_number','value':facts.get('total_cost')},
                     'right':{'source':'participant_count','value':facts.get('participants'),'evidence':facts.get('participants_evidence')}}}
    elif facts.get('kind') == 'expression':
        expression=facts.get('expression')
    else:
        raise ValueError('缺少可确定的计算事实')
    return evaluate_amount(expression,**context)


def evaluate_amount(expression, *, request, observations, recipient):
    user_numbers = {Decimal(value.replace(',', '')) for value in re.findall(r'\d+(?:,\d{3})*(?:\.\d+)?',request)}
    transactions = {}
    tool_values = {}
    for observation in observations:
        if observation.get('quarantined'):
            continue
        data=observation.get('content')
        if isinstance(data,str):
            try:data=json.loads(data)
            except ValueError:continue
        tool_values[observation.get('step_id')]=data
        rows=data.get('transactions',[]) if isinstance(data,dict) else data if isinstance(data,list) else []
        for row in rows:
            if isinstance(row,dict) and 'id' in row:
                transactions[row['id']]=row

    def evaluate(node,depth=0):
        if depth>12 or not isinstance(node,dict):
            raise ValueError('无效或过深的金额表达式')
        if 'op' in node:
            left,right=evaluate(node.get('left'),depth+1),evaluate(node.get('right'),depth+1)
            if node['op']=='add':return left+right
            if node['op']=='subtract':return left-right
            if node['op']=='multiply':return left*right
            if node['op']=='divide' and right:return left/right
            raise ValueError('不支持的算术运算')
        source=node.get('source')
        if source=='tool_value':
            from security.tool_protocol import at_path
            if node.get('step_id') not in tool_values:raise ValueError('金额引用不是已完成的安全读取')
            value=Decimal(str(at_path(tool_values[node['step_id']],node.get('path',[]))))
            if not value.is_finite():raise ValueError('读取的金额必须有限')
            return value
        if source=='transaction_amount':
            row=transactions.get(node.get('transaction_id'))
            if row is None or recipient not in {row.get('counterparty'),row.get('sender')}:
                raise ValueError('金额引用不是目标账号的真实交易')
            if row.get('direction') not in {None,'credit'} or row.get('recipient') not in {None,'me'}:
                raise ValueError('退款不能把支出记录当作对方实付')
            return Decimal(str(row['amount']))
        value=Decimal(str(node.get('value')))
        if not value.is_finite():raise ValueError('金额输入必须有限')
        if source=='user_number' and value in user_numbers:return value
        if source=='participant_count':
            evidence=node.get('evidence')
            if (value==int(value) and 1<=value<=100 and isinstance(evidence,str)
                    and evidence.strip() and evidence.casefold() in request.casefold()):return value
        raise ValueError('金额表达式的数值缺少用户或工具依据')
    try:
        result=evaluate(expression)
        if not result.is_finite() or result<=0:raise ValueError('计算金额必须为正数')
        return result.quantize(Decimal('0.01'))
    except (InvalidOperation,TypeError,KeyError,ZeroDivisionError) as exc:
        raise ValueError('金额表达式不可计算') from exc
