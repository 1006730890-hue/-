def test_recent_transactions_use_dates_with_stable_id_ties(app_modules):
    from app import tools

    with app_modules['db'].db() as conn:
        conn.executemany('''INSERT INTO transactions(id,user_id,ts,category,amount,txn_type)
                            VALUES(?,?,?,?,?,?)''',[
            (2001,42,'2031-04-08','餐饮',1,'expense'),
            (2002,42,'2031-04-01','餐饮',2,'expense'),
            (2003,42,'2031-04-05','餐饮',3,'expense'),
            (2004,42,'2031-04-08','餐饮',4,'expense'),
            (2005,42,'2031-04-09','交通',5,'expense'),
            (2006,43,'2031-04-10','餐饮',6,'expense'),
        ])

    result = tools.list_transactions(42,{'category':'餐饮','limit':3})
    assert result['count'] == 3
    assert [row['id'] for row in result['transactions']] == [2004,2001,2003]
