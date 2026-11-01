"""初始化演示数据。重复执行会清空重建。"""
from datetime import date, timedelta
from .db import db, init_db


def seed():
    init_db()
    with db() as conn:
        for t in ["users", "accounts", "cards", "transactions", "subscriptions",
                  "wealth_products", "holdings", "audit_logs", "pending_actions", "goals", "recipients", "scheduled_transfers", "aa_requests"]:
            conn.execute(f"DELETE FROM {t}")

        conn.execute("INSERT INTO users(id,name,phone,token,risk_level) VALUES(1,?,?,?,?)",
                     ("张伟", "13800000001", "guest001", "稳健型"))
        conn.execute("INSERT INTO accounts(id,user_id,account_no,balance) VALUES(1,1,?,?)",
                     ("622202****8888", 52318.50))
        conn.execute("""INSERT INTO cards(id,user_id,card_no,holder,card_type,status,credit_limit,remaining_limit)
                        VALUES(1,1,?,?,?,?,?,?)""",
                     ("621700****1234", "张伟", "借记卡", "normal", 0, 0))
        conn.execute("""INSERT INTO cards(id,user_id,card_no,holder,card_type,status,credit_limit,remaining_limit)
                        VALUES(2,1,?,?,?,?,?,?)""",
                     ("625907****5678", "张伟", "信用卡", "normal", 50000, 32410.75))

        base = date.today()
        rows = [
            ("星巴克", "餐饮", 38.0, "expense"), ("美团外卖", "餐饮", 26.5, "expense"),
            ("海底捞", "餐饮", 189.0, "expense"), ("滴滴出行", "交通", 23.6, "expense"),
            ("地铁", "交通", 6.0, "expense"), ("京东", "购物", 599.0, "expense"),
            ("淘宝", "购物", 268.0, "expense"), ("爱奇艺", "娱乐", 25.0, "expense"),
            ("电影院", "娱乐", 88.0, "expense"), ("全家", "日用", 45.8, "expense"),
            ("工资", "工资", 18000.0, "income"), ("网易云音乐", "订阅", 15.0, "expense"),
            ("健身房", "订阅", 300.0, "expense"),
        ]
        rid = 1
        for days_ago in [2, 6, 10, 16, 22]:
            for name, cat, amt, typ in rows:
                ts = (base - timedelta(days=days_ago)).isoformat()
                conn.execute("""INSERT INTO transactions(id,user_id,ts,counterparty,category,amount,txn_type,merchant)
                                VALUES(?,?,?,?,?,?,?,?)""",
                             (rid, 1, ts, name, cat, amt, typ, name))
                rid += 1
        conn.execute("""INSERT INTO transactions(id,user_id,ts,counterparty,category,amount,txn_type,merchant)
                        VALUES(?,?,?,?,?,?,?,?)""",
                     (rid, 1, (base - timedelta(days=1)).isoformat(), "未知商户(深圳)",
                      "境外消费", 9999.0, "expense", "UNKNOWN-POS"))

        conn.execute("""INSERT INTO subscriptions(id,user_id,name,amount,cycle,next_charge,status)
                        VALUES(1,1,?,?,?,?,?)""",
                     ("网易云音乐", 15.0, "月", (base + timedelta(days=5)).isoformat(), "active"))
        conn.execute("""INSERT INTO subscriptions(id,user_id,name,amount,cycle,next_charge,status)
                        VALUES(2,1,?,?,?,?,?)""",
                     ("爱奇艺黄金会员", 25.0, "月", (base + timedelta(days=12)).isoformat(), "active"))
        conn.execute("""INSERT INTO subscriptions(id,user_id,name,amount,cycle,next_charge,status)
                        VALUES(3,1,?,?,?,?,?)""",
                     ("乐刻健身房", 300.0, "月", (base + timedelta(days=3)).isoformat(), "active"))

        products = [
            ("安稳盈90天(R1低风险)", "R1", 2.1, 1000, "定期理财"),
            ("稳健添利(R2中低风险)", "R2", 3.4, 1000, "定开理财"),
            ("蓝筹混合基金(R3中风险)", "R3", 8.5, 10, "公募基金"),
            ("沪深300指数增强(R4中高风险)", "R4", 12.0, 10, "指数基金"),
        ]
        for i, (n, r, y, m, p) in enumerate(products, start=1):
            conn.execute("""INSERT INTO wealth_products(id,name,risk_level,annual_return,min_amount,ptype)
                            VALUES(?,?,?,?,?,?)""", (i, n, r, y, m, p))

        conn.execute("INSERT INTO holdings(id,user_id,product_name,amount) VALUES(1,1,?,?)",
                     ("安稳盈90天(R1低风险)", 20000.0))

        conn.executemany('INSERT INTO recipients(id,user_id,name,phone,account_no,label) VALUES(?,?,?,?,?,?)',[
            (1,1,'张三','13800000002','LOCAL-1001','同事'),
            (2,1,'张三','13800000003','LOCAL-1002','朋友'),
            (3,1,'李四','13800000004','LOCAL-1003','家人')])

    print("[seed] 演示数据已初始化：用户=张伟 余额=52318.50")


if __name__ == "__main__":
    seed()
