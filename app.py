from flask import Flask, request, render_template
import os, re
from datetime import datetime

app = Flask(__name__)
# 自动在项目同级创建“留言”文件夹
MSG_DIR = os.path.join(os.path.dirname(__file__), '留言')
os.makedirs(MSG_DIR, exist_ok=True)

def clean_name(name):
    # 仅保留中英文、数字、下划线，防路径穿越与非法文件名
    return re.sub(r'[^\w\u4e00-\u9fa5]', '', name)[:32] or '匿名'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        nickname = request.form.get('nickname', '').strip()
        message = request.form.get('message', '').strip()
        
        if not nickname or not message or len(nickname)>32 or len(message)>2048:
            return "输入不合规", 400
            
        safe_name = clean_name(nickname)
        file_path = os.path.join(MSG_DIR, f"留言_{safe_name}.txt")
        
        ip = request.remote_addr or '[2408:825c:2e2:68a3:45cb:ebb0:a640:63ff]:5033'
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 注：使用文件存储天然规避SQL注入。此处已做安全过滤。
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"{ip} {ts}\n{message}")
            
        return "<h3>留言成功</h3><a href='/'>返回首页</a>"
        
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, port=5033)