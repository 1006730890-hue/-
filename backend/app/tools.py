"""银行业务工具集：每个工具是一个纯函数，供 Agent 调用。"""
from datetime import datetime
from .db import db, transaction
from .money import transfer_amount
from . import config


class ToolError(Exception):
    pass


def get_balance(user_id, args):
    with db() as conn:
        row = conn.execute("SELECT * FROM accounts WHERE user_id=?", (user_id,)).fetchone()
        card = conn.execute("SELECT * FROM cards WHERE user_id=? AND card_type='信用卡'", (user_id,)).fetchone()
    return {"ok": True, "balance": row["balance"], "account_no": row["account_no"],
            "credit_remaining": card["remaining_limit"] if card else 0}


def list_transactions(user_id, args):
    limit = int(args.get("limit", 20))
    category = args.get("category")
    sql = "SELECT * FROM transactions WHERE user_id=?"
    params = [user_id]
    if category:
        sql += " AND category=?"
        params.append(category)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    return {"ok": True, "count": len(rows), "transactions": rows}


def monthly_bill(user_id, args):
    ym = args.get("year_month") or datetime.now().strftime("%Y-%m")
    with db() as conn:
        rows = conn.execute(
            "SELECT category, SUM(amount) AS total FROM transactions WHERE user_id=? AND ts LIKE ? AND txn_type='expense' GROUP BY category",
            (user_id, ym + "%")).fetchall()
        total = conn.execute(
            "SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE user_id=? AND ts LIKE ? AND txn_type='expense'",
            (user_id, ym + "%")).fetchone()["s"]
    return {"ok": True, "year_month": ym, "total_expense": round(total, 2),
            "by_category": {r["category"]: round(r["total"], 2) for r in rows}}


def detect_anomaly(user_id, args):
    with db() as conn:
        avg = conn.execute(
            "SELECT AVG(amount) AS a FROM transactions WHERE user_id=? AND txn_type='expense' AND category!='境外消费'",
            (user_id,)).fetchone()["a"] or 0
        rows = conn.execute(
            "SELECT * FROM transactions WHERE user_id=? AND txn_type='expense' AND amount > ?",
            (user_id, max(avg * 5, 500))).fetchall()
    threshold = round(max(avg * 5, 500),2)
    flagged = [dict(r,reason=f'金额超过异常阈值 {threshold:.2f} 元',baseline=round(avg,2),evidence_id=f"txn-{r['id']}") for r in rows]
    return {"ok": True, "threshold": threshold, "avg_txn": round(avg, 2), "anomalies": flagged,
            "message": f"检测到 {len(flagged)} 笔异常交易，请核对" if flagged else "近期交易未发现明显异常"}


def list_cards(user_id, args):
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM cards WHERE user_id=?", (user_id,)).fetchall()]
    return {"ok": True, "cards": rows}


def list_subscriptions(user_id, args):
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM subscriptions WHERE user_id=? AND status='active'", (user_id,)).fetchall()]
    return {"ok": True, "subscriptions": rows, "monthly_total": round(sum(r["amount"] for r in rows), 2)}


def cancel_subscription(user_id, args):
    name = args.get("name", "")
    if not name or any(c in name for c in "%_"):
        raise ToolError("请明确要取消的订阅名称")
    with db() as conn:
        cur = conn.execute(
            "UPDATE subscriptions SET status='canceled' WHERE user_id=? AND name LIKE ? AND status='active'",
            (user_id, f"%{name}%"))
        if cur.rowcount == 0:
            raise ToolError(f"未找到进行中的订阅：{name}")
    return {"ok": True, "canceled": name}


def list_wealth_products(user_id, args):
    risk = args.get("risk_level")
    sql, params = "SELECT * FROM wealth_products", []
    if risk:
        sql += " WHERE risk_level=?"
        params.append(risk)
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    return {"ok": True, "products": rows}


def compare_products(user_id, args):
    names = args.get("names", [])
    rows = []
    with db() as conn:
        for n in names:
            r = conn.execute("SELECT * FROM wealth_products WHERE name LIKE ?", (f"%{n}%",)).fetchone()
            if r:
                rows.append(dict(r))
    if not rows:
        raise ToolError("未找到匹配的产品")
    return {"ok": True, "compared": rows}


def get_holdings(user_id, args):
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM holdings WHERE user_id=?", (user_id,)).fetchall()]
    return {"ok": True, "holdings": rows}


def valid_amount(value):
    try:
        return transfer_amount(value)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def transfer(user_id, args):
    to_name = args.get('to_name') or args.get('name')
    to_phone = args.get('to_phone') or args.get('phone', '')
    amount = valid_amount(args.get('amount'))
    if not isinstance(to_name, str) or not to_name.strip() or len(to_name) > 100:
        raise ToolError('请提供有效收款人')
    note = args.get('note', '')
    with transaction() as conn:
        from .security import today_transfer_total
        if round(today_transfer_total(user_id) + amount, 2) > config.settings.DAILY_TRANSFER_LIMIT:
            raise ToolError('超出单日转账上限')
        acc = conn.execute('SELECT * FROM accounts WHERE user_id=?', (user_id,)).fetchone()
        if not acc:
            raise ToolError('账户不存在')
        if int(round(amount * 100)) > int(round(acc['balance'] * 100)):
            raise ToolError(f"余额不足：当前可用 {acc['balance']:.2f} 元")
        # A debit and its receipt are committed together; confirmation owns the outer transaction.
        cur = conn.execute('UPDATE accounts SET balance=ROUND(balance-?,2) WHERE user_id=? AND balance>=?', (amount,user_id,amount))
        if cur.rowcount != 1:
            raise ToolError('余额不足')
        cur = conn.execute('''INSERT INTO transactions(user_id,ts,counterparty,category,amount,txn_type,merchant)
                              VALUES(?,?,?,?,?,?,?)''',
                           (user_id,datetime.now().isoformat(timespec='seconds'),f'{to_name}({to_phone})','转账',amount,'transfer_out',note))
        transaction_id = cur.lastrowid
    return {'ok': True,'to_name': to_name,'amount': amount,'note': note,'transaction_id': transaction_id,
            'settlement': 'local_ledger', 'currency': 'CNY'}


def purchase_wealth(user_id, args):
    name = args.get("product_name")
    amount = valid_amount(args.get("amount"))
    with transaction() as conn:
        p = conn.execute("SELECT * FROM wealth_products WHERE name LIKE ?", (f"%{name}%",)).fetchone()
        if not p:
            raise ToolError(f"未找到产品：{name}")
        profile = conn.execute('SELECT risk_level FROM users WHERE id=?',(user_id,)).fetchone()
        ceiling = {'保守型':1,'稳健型':2,'平衡型':3,'进取型':4,'激进型':4}.get(profile['risk_level'] if profile else '',1)
        if int(p['risk_level'][1:]) > ceiling:
            raise ToolError('风险不匹配：产品风险超过当前客户评估等级')
        if amount < p["min_amount"]:
            raise ToolError(f"该产品起购金额 {p['min_amount']} 元")
        acc = conn.execute("SELECT * FROM accounts WHERE user_id=?", (user_id,)).fetchone()
        if amount > acc["balance"]:
            raise ToolError("余额不足")
        conn.execute("UPDATE accounts SET balance=ROUND(balance-?,2) WHERE user_id=?", (amount, user_id))
        existing = conn.execute("SELECT * FROM holdings WHERE user_id=? AND product_name=?",
                               (user_id, p["name"])).fetchone()
        if existing:
            conn.execute("UPDATE holdings SET amount=ROUND(amount+?,2) WHERE id=?", (amount, existing["id"]))
        else:
            conn.execute("INSERT INTO holdings(user_id,product_name,amount) VALUES(?,?,?)",
                         (user_id, p["name"], amount))
    return {"ok": True, "product": p["name"], "amount": amount, "risk_level": p["risk_level"]}


def redeem_wealth(user_id, args):
    name = args.get("product_name")
    amount = valid_amount(args.get("amount"))
    with transaction() as conn:
        h = conn.execute("SELECT * FROM holdings WHERE user_id=? AND product_name LIKE ?",
                         (user_id, f"%{name}%")).fetchone()
        if not h:
            raise ToolError(f"未持有该产品：{name}")
        if amount > h["amount"]:
            raise ToolError(f"持有份额不足，当前 {h['amount']:.2f} 元")
        conn.execute("UPDATE holdings SET amount=ROUND(amount-?,2) WHERE id=?", (amount, h["id"]))
        conn.execute("UPDATE accounts SET balance=ROUND(balance+?,2) WHERE user_id=?", (amount, user_id))
    return {"ok": True, "product": h["product_name"], "redeemed": amount}


def toggle_card_freeze(user_id, args):
    card_id = int(args.get("card_id", 0))
    new_status = "frozen" if args.get("action") == "freeze" else "normal"
    with db() as conn:
        cur = conn.execute("UPDATE cards SET status=? WHERE id=? AND user_id=? AND status!='reported'",
                           (new_status, card_id, user_id))
        if cur.rowcount == 0:
            raise ToolError("卡片不存在或已挂失")
    return {"ok": True, "card_id": card_id, "status": new_status}


def report_card_loss(user_id, args):
    card_id = int(args.get("card_id", 0))
    with db() as conn:
        cur = conn.execute("UPDATE cards SET status='reported' WHERE id=? AND user_id=?",
                           (card_id, user_id))
        if cur.rowcount == 0:
            raise ToolError("卡片不存在")
    return {"ok": True, "card_id": card_id, "status": "reported"}


def adjust_credit_limit(user_id, args):
    card_id = int(args.get("card_id", 0))
    new_limit = valid_amount(args.get("new_limit"))
    if new_limit <= 0:
        raise ToolError("额度必须为正数")
    with db() as conn:
        cur = conn.execute("UPDATE cards SET credit_limit=? WHERE id=? AND user_id=? AND card_type='信用卡'",
                           (new_limit, card_id, user_id))
        if cur.rowcount == 0:
            raise ToolError("仅信用卡可调整额度")
    return {"ok": True, "card_id": card_id, "new_limit": new_limit}


def create_goal(user_id, args):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO goals(user_id,description,due_date,plan) VALUES(?,?,?,?)",
            (user_id, args.get("description", ""), args.get("due_date", ""), args.get("plan", "")))
        return {"ok": True, "goal_id": cur.lastrowid,
                "description": args.get("description", ""), "due_date": args.get("due_date", "")}


def list_goals(user_id, args):
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM goals WHERE user_id=? AND status='active'", (user_id,)).fetchall()]
    return {"ok": True, "goals": rows}


TOOLS = {
    "get_balance": get_balance, "list_transactions": list_transactions,
    "monthly_bill": monthly_bill, "detect_anomaly": detect_anomaly,
    "list_cards": list_cards, "list_subscriptions": list_subscriptions,
    "cancel_subscription": cancel_subscription, "list_wealth_products": list_wealth_products,
    "compare_products": compare_products, "get_holdings": get_holdings,
    "transfer": transfer, "purchase_wealth": purchase_wealth,
    "redeem_wealth": redeem_wealth, "toggle_card_freeze": toggle_card_freeze,
    "report_card_loss": report_card_loss, "adjust_credit_limit": adjust_credit_limit,
    "create_goal": create_goal, "list_goals": list_goals,
}

def _fn(name, desc, props=None, required=None):
    props = props or {}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": schema}}


TOOL_SCHEMAS = [
    _fn("get_balance", "查询账户余额与信用卡可用额度"),
    _fn("list_transactions", "查询交易记录，可按分类筛选", {"limit": {"type": "integer"}, "category": {"type": "string"}}),
    _fn("monthly_bill", "按月生成账单分类统计", {"year_month": {"type": "string", "description": "YYYY-MM"}}),
    _fn("detect_anomaly", "识别异常/可疑交易"),
    _fn("list_cards", "查询名下银行卡及状态"),
    _fn("list_subscriptions", "查询所有自动续费/订阅代扣"),
    _fn("cancel_subscription", "取消某个订阅代扣", {"name": {"type": "string"}}, ["name"]),
    _fn("list_wealth_products", "查询理财产品列表，可按风险等级筛选", {"risk_level": {"type": "string", "enum": ["R1","R2","R3","R4"]}}),
    _fn("compare_products", "对比几款理财产品", {"names": {"type": "array", "items": {"type": "string"}}}),
    _fn("get_holdings", "查询当前理财持仓"),
    _fn("transfer", "本地账本转账：必填收款人姓名 to_name 和金额 amount；手机号 to_phone 可省略，不因缺少手机号而询问。不连接银行清算网络", {"to_name": {"type": "string"}, "to_phone": {"type": "string"}, "amount": {"type": "number"}, "note": {"type": "string"}}, ["to_name","amount"]),
    _fn("purchase_wealth", "申购理财产品", {"product_name": {"type": "string"}, "amount": {"type": "number"}}, ["product_name","amount"]),
    _fn("redeem_wealth", "赎回理财产品", {"product_name": {"type": "string"}, "amount": {"type": "number"}}, ["product_name","amount"]),
    _fn("toggle_card_freeze", "冻结/解冻自己的卡片", {"card_id": {"type": "integer"}, "action": {"type": "string", "enum": ["freeze","unfreeze"]}}, ["card_id","action"]),
    _fn("report_card_loss", "银行卡挂失（高风险）", {"card_id": {"type": "integer"}}, ["card_id"]),
    _fn("adjust_credit_limit", "调整信用卡额度", {"card_id": {"type": "integer"}, "new_limit": {"type": "number"}}, ["card_id","new_limit"]),
    _fn("create_goal", "创建定时/跨场景目标任务，例如生日前订花", {"description": {"type": "string"}, "due_date": {"type": "string"}, "plan": {"type": "string"}}, ["description"]),
    _fn("list_goals", "查看已创建的目标任务"),
]


def spending_report(user_id,args):
    from datetime import date
    months = args.get('months',12)
    if isinstance(months,bool) or not isinstance(months,int) or not 1 <= months <= 36:
        raise ToolError('月份范围须为1至36')
    current = date.today().year*12+date.today().month-1
    labels = [f'{index//12:04d}-{index%12+1:02d}' for index in range(current-months+1,current+1)]
    with db() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM transactions WHERE user_id=? AND txn_type='expense' AND substr(ts,1,7)>=? AND substr(ts,1,7)<=? ORDER BY ts",(user_id,labels[0],labels[-1]))]
    totals = {label:0 for label in labels}
    categories = {}
    for row in rows:
        label = row['ts'][:7]
        if label in totals:
            totals[label] += row['amount']
            categories[row['category']] = categories.get(row['category'],0)+row['amount']
    total = round(sum(totals.values()),2)
    prior = totals[labels[-2]] if len(labels)>1 else 0
    latest = totals[labels[-1]]
    change = round((latest-prior)/prior*100,2) if prior else (0 if latest == 0 else None)
    return {'ok':True,'monthly_trend':[{'month':key,'expense':round(value,2)} for key,value in totals.items()],
            'total_expense':total,'category_ranking':[{'category':k,'amount':round(v,2),'share':round(v/total,6) if total else 0} for k,v in sorted(categories.items(),key=lambda item:-item[1])],
            'month_over_month_pct':change,'evidence':[{**r,'evidence_id':f"txn-{r['id']}"} for r in rows]}


def recommend_wealth(user_id,args):
    amount = valid_amount(args.get('amount'))
    horizon = args.get('horizon_months',12)
    if isinstance(horizon,bool) or not isinstance(horizon,int) or not 1 <= horizon <= 120:
        raise ToolError('投资期限须为1至120个月')
    with db() as conn:
        user = conn.execute('SELECT risk_level FROM users WHERE id=?',(user_id,)).fetchone()
        if not user:
            raise ToolError('用户不存在')
        ceiling = {'保守型':1,'稳健型':2,'平衡型':3,'进取型':4,'激进型':4}.get(user['risk_level'],1)
        products = [dict(r) for r in conn.execute('SELECT * FROM wealth_products WHERE min_amount<=?',(amount,)) if int(r['risk_level'][1:])<=ceiling]
    return {'ok':True,'user_risk':user['risk_level'],'risk_ceiling':f'R{ceiling}',
            'recommendations':[{**p,'guaranteed_return':False,'reason':'起购金额与已评估的风险等级相符'} for p in products],
            'horizon_months':horizon,'disclaimer':'理财非存款，历史业绩不代表未来表现；请阅读产品条款与期限约束。'}


def find_recipients(user_id,args):
    name = args.get('name','')
    if not isinstance(name,str) or not name or any(c in name for c in '%_'):
        raise ToolError('请提供收款人姓名')
    with db() as conn:
        rows = conn.execute('SELECT * FROM recipients WHERE user_id=? AND name LIKE ?',(user_id,'%'+name+'%')).fetchall()
    candidates = [{'id':r['id'],'name':r['name'],'label':r['label'],'account_masked':'**** '+r['account_no'][-4:]} for r in rows]
    return {'ok':True,'candidates':candidates,'requires_disambiguation':len(candidates)>1}


def schedule_transfer(user_id,args):
    from datetime import timezone
    amount = valid_amount(args.get('amount'))
    try:
        at = datetime.fromisoformat(args.get('execute_at',''))
        if at.tzinfo is None or at <= datetime.now(timezone.utc):
            raise ValueError('not a future timezone-aware timestamp')
    except (ValueError,TypeError) as exc:
        raise ToolError('预约时间须为包含时区的未来时间') from exc
    with transaction() as conn:
        recipient = conn.execute('SELECT * FROM recipients WHERE id=? AND user_id=?',(args.get('recipient_id'),user_id)).fetchone()
        if not recipient:
            raise ToolError('收款人不存在或不属于当前用户')
        cur = conn.execute("INSERT INTO scheduled_transfers(user_id,recipient_id,amount,execute_at,note,created_at) VALUES(?,?,?,?,?,?)",
                           (user_id,recipient['id'],amount,at.astimezone(timezone.utc).isoformat(),args.get('note',''),datetime.now(timezone.utc).isoformat()))
    return {'ok':True,'schedule_id':cur.lastrowid,'status':'scheduled','requires_pre_execution_review':True,'debited':False,'amount':amount}


def create_aa_request(user_id,args):
    from decimal import Decimal,ROUND_HALF_UP
    total = valid_amount(args.get('total_amount'))
    count = args.get('participant_count')
    title = args.get('title','')
    if isinstance(count,bool) or not isinstance(count,int) or not 2 <= count <= 100 or not isinstance(title,str) or not title.strip():
        raise ToolError('请指定AA主题与2至100名参与人')
    per = float((Decimal(str(total))/count).quantize(Decimal('.01'),rounding=ROUND_HALF_UP))
    with db() as conn:
        cur = conn.execute('INSERT INTO aa_requests(user_id,title,total_amount,participant_count,per_person,created_at) VALUES(?,?,?,?,?,?)',
                           (user_id,title,total,count,per,datetime.now().isoformat()))
    return {'ok':True,'request_id':cur.lastrowid,'per_person':per,'status':'open','debited':False,
            'rounding_difference':round(total-per*count,2)}


TOOLS.update(spending_report=spending_report,recommend_wealth=recommend_wealth,find_recipients=find_recipients,
             schedule_transfer=schedule_transfer,create_aa_request=create_aa_request)
TOOL_SCHEMAS.extend([
    _fn('spending_report','按真实流水生成消费趋势与分类报告',{'months':{'type':'integer','minimum':1,'maximum':36}}),
    _fn('recommend_wealth','按客户已评估风险与起购金额筛选理财产品，不承诺收益',{'amount':{'type':'number'},'horizon_months':{'type':'integer','minimum':1,'maximum':120}},['amount']),
    _fn('find_recipients','检索本人已登记收款人，重名时返回候选编号及账号尾号',{'name':{'type':'string'}},['name']),
    _fn('schedule_transfer','登记预约转账，到期仍须重新安全检查与用户确认，当前不扣款',{'recipient_id':{'type':'integer'},'amount':{'type':'number'},'execute_at':{'type':'string'},'note':{'type':'string'}},['recipient_id','amount','execute_at']),
    _fn('create_aa_request','登记AA收款请求，不自动扣款或对外发送消息',{'title':{'type':'string'},'total_amount':{'type':'number'},'participant_count':{'type':'integer','minimum':2,'maximum':100}},['title','total_amount','participant_count'])
])
