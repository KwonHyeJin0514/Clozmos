import requests
import time

ZABBIX_API_URL = "http://172.29.109.42/zabbix/api_jsonrpc.php"

def _post(payload):
    headers = {'Content-Type': 'application/json-rpc'}
    res = requests.post(ZABBIX_API_URL, json=payload, headers=headers)
    return res.json()

def get_auth_token(user, password):
    return _post({
        "jsonrpc": "2.0", "method": "user.login",
        "params": {"user": user, "password": password},
        "id": 1
    })["result"]

def get_all_hosts(token):
    return _post({
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {"output": ["hostid", "host"]},
        "auth": token, "id": 2
    })["result"]

def get_user_host(token, username, return_id=False):
    for h in get_all_hosts(token):
        if h['host'] == username:
            return h['hostid'] if return_id else h['host']
    raise Exception(f"Host for user '{username}' not found.")

def get_item_id(token, host_id, item_key):
    res = _post({
        "jsonrpc": "2.0", "method": "item.get",
        "params": {
            "output": ["itemid"], "hostids": host_id,
            "search": {"key_": item_key}, "sortfield": "name"
        },
        "auth": token, "id": 3
    })
    if res["result"]:
        return res["result"][0]["itemid"]
    raise Exception(f"Item '{item_key}' not found.")

def get_latest_data(token, item_id, limit=10):
    res = _post({
        "jsonrpc": "2.0", "method": "history.get",
        "params": {
            "output": "extend", "history": 0,
            "itemids": item_id, "sortfield": "clock",
            "sortorder": "DESC", "limit": limit
        },
        "auth": token, "id": 4
    })
    return list(reversed(res["result"]))

def get_user_info(token):
    return _post({
        "jsonrpc": "2.0",
        "method": "user.get",
        "params": {
            "output": "extend",
            "selectMedias": "extend"
        },
        "auth": token,
        "id": 5
    })["result"][0]

def create_zabbix_user(admin_token, username, password, email):
    return _post({
        "jsonrpc": "2.0", "method": "user.create",
        "params": {
            "username": username,
            "passwd": password,
            "name": username,
            "surname": "-",
            "groups": [{"usrgrpid": "7"}],
            "user_medias": [{
                "mediatypeid": "1",
                "sendto": email,
                "active": 0,
                "severity": 63,
                "period": "1-7,00:00-24:00"
            }]
        },
        "auth": admin_token, "id": 12
    })


def update_user_field(token, field, value):
    user = get_user_info(token)
    userid = user["userid"]

    if field == "email" or field == "alert_email":
        payload = {
            "jsonrpc": "2.0",
            "method": "user.update",
            "params": {
                "userid": userid,
                "user_medias": [{
                    "mediatypeid": "1",
                    "sendto": value,
                    "active": 0,
                    "severity": 63,
                    "period": "1-7,00:00-24:00"
                }]
            },
            "auth": token,
            "id": 6
        }
    else:
        payload = {
            "jsonrpc": "2.0",
            "method": "user.update",
            "params": {
                "userid": userid,
                field: value
            },
            "auth": token,
            "id": 6
        }

    return _post(payload)


def validate_user_password(token, current_password):
    user = get_user_info(token)
    try:
        temp_token = get_auth_token(user["username"], current_password)
        return True
    except:
        return False

def delete_user_account(token):
    user = get_user_info(token)
    userid = user["userid"]
    return _post({
        "jsonrpc": "2.0", "method": "user.delete",
        "params": [userid],
        "auth": token, "id": 7
    })

def get_alert_logs(token, host_name, max_logs=7):
    host_id = get_user_host(token, host_name, return_id=True)
    
    events = _post({
        "jsonrpc": "2.0",
        "method": "event.get",
        "params": {
            "output": ["clock", "value"], 
            "select_triggers": ["description", "priority"],
            "hostids": host_id,
            "sortfield": ["clock", "eventid"],
            "sortorder": "DESC",
            "time_from": int(time.time()) - (24 * 3600 * 7), 
            "min_severity": 3, 
            "limit": 20
        },
        "auth": token, "id": 8
    })["result"]

    results = []
    
    for event in events:
        # 이벤트가 Problem (1) 상태가 아니거나, 연결된 트리거가 없다면 건너뜀
        if int(event.get("value", 0)) == 0 or not event.get("triggers"):
            continue
            
        # ⚠️ 안전하게 첫 번째 트리거를 가져옵니다.
        trigger = event["triggers"][0]
        
        ts = int(event["clock"])
        level = int(trigger["priority"])
        
        # 심각도에 따른 색상 설정: Critical(4) 이상은 red, Warning(3)은 orange
        color = "red" if level >= 4 else "orange" if level == 3 else "black"
        
        results.append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)),
            "message": trigger["description"],
            "color": color
        })

        if len(results) >= max_logs:
            break
            
    return results