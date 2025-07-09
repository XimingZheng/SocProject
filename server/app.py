#!/usr/bin/env python3
"""
Flask后端安全扫描服务器
为Chrome扩展提供多线程安全扫描服务
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
import threading
import time
import uuid
import logging
from datetime import datetime
from werkzeug.serving import WSGIRequestHandler
from typing import Dict, Any

from manager import ThreadSafeScannerManager
from scanners.HeaderScanner import HeaderScanner

# ========================
# 基础配置
# ========================

app = Flask(__name__)
CORS(app)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# 全局任务存储
scan_tasks: Dict[str, Any] = {}
task_results: Dict[str, Any] = {}

# ========================
# API 路由
# ========================

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})

        if not url:
            return jsonify({'error': '缺少URL参数'}), 400

        task_id = str(uuid.uuid4())

        def run_scan_task():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                scanner_manager = ThreadSafeScannerManager()
                result = loop.run_until_complete(scanner_manager.scan_website(url, headers_data))

                task_results[task_id] = {'status': 'completed', 'result': result}
                loop.close()

            except Exception as e:
                logger.error(f"扫描任务 {task_id} 失败: {e}")
                task_results[task_id] = {'status': 'failed', 'error': str(e)}

        scan_thread = threading.Thread(target=run_scan_task, daemon=True)
        scan_thread.start()

        scan_tasks[task_id] = {
            'status': 'running',
            'url': url,
            'start_time': time.time(),
            'thread': scan_thread
        }

        task_results[task_id] = {'status': 'running'}

        return jsonify({'task_id': task_id, 'status': 'started', 'message': '扫描任务已启动'})

    except Exception as e:
        logger.error(f"启动扫描任务失败: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/status/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    try:
        if task_id not in task_results:
            return jsonify({'error': '任务不存在'}), 404

        task_result = task_results[task_id]
        task_info = scan_tasks.get(task_id, {})

        response = {'task_id': task_id, 'status': task_result['status']}

        if task_result['status'] == 'completed':
            response['result'] = task_result['result']
            scan_tasks.pop(task_id, None)
            task_results.pop(task_id, None)
        elif task_result['status'] == 'failed':
            response['error'] = task_result['error']
            scan_tasks.pop(task_id, None)
            task_results.pop(task_id, None)
        elif task_result['status'] == 'running':
            response['elapsed_time'] = time.time() - task_info.get('start_time', time.time())

        return jsonify(response)

    except Exception as e:
        logger.error(f"获取任务状态失败: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})

        if not url:
            return jsonify({'error': '缺少URL参数'}), 400

        scanner = HeaderScanner()

        async def quick_scan_task():
            response_data = {
                'headers': headers_data,
                'content': '',
                'status': 200,
                'url': url
            }
            return await scanner.scan(None, url, response_data)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(quick_scan_task())
        loop.close()

        high_risk = [r for r in results if r.risk_level == 'high']
        medium_risk = [r for r in results if r.risk_level == 'medium']
        low_risk = [r for r in results if r.risk_level == 'low']

        security_score = max(0, 100 - (len(high_risk) * 20 + len(medium_risk) * 10 + len(low_risk) * 5))

        if len(high_risk) >= 2 or security_score < 40:
            overall_risk = 'high'
        elif len(high_risk) >= 1 or len(medium_risk) >= 2 or security_score < 70:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'

        return jsonify({
            'url': url,
            'scan_type': 'quick',
            'security_score': security_score,
            'risk_level': overall_risk,
            'total_issues': len(results),
            'statistics': {
                'high_risk': len(high_risk),
                'medium_risk': len(medium_risk),
                'low_risk': len(low_risk)
            },
            'issues': [r.to_dict() for r in results],
            'summary': f"发现 {len(results)} 个响应头安全问题" if results else "响应头配置良好"
        })

    except Exception as e:
        logger.error(f"快速扫描失败: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'active_tasks': len(scan_tasks)
    })


@app.route('/api/scanners', methods=['GET'])
def get_available_scanners():
    scanners_info = [
        {
            'name': 'Header Scanner',
            'description': '检测HTTP安全响应头配置',
            'vulnerability_types': ['Missing Security Header', 'Misconfigured Security Header']
        },
        {
            'name': 'XSS Scanner',
            'description': '检测跨站脚本攻击漏洞',
            'vulnerability_types': ['Cross-Site Scripting (XSS)']
        },
        {
            'name': 'SQL Injection Scanner',
            'description': '检测SQL注入漏洞',
            'vulnerability_types': ['SQL Injection']
        },
        {
            'name': 'SSL Scanner',
            'description': '检测SSL/TLS配置问题',
            'vulnerability_types': ['Insecure Protocol']
        }
    ]

    return jsonify({
        'scanners': scanners_info,
        'total_scanners': len(scanners_info)
    })

# ========================
# 清理过期任务
# ========================

def cleanup_expired_tasks():
    while True:
        try:
            current_time = time.time()
            expired = [task_id for task_id, info in scan_tasks.items()
                       if current_time - info.get('start_time', current_time) > 600]
            for task_id in expired:
                logger.info(f"清理过期任务: {task_id}")
                scan_tasks.pop(task_id, None)
                task_results.pop(task_id, None)
            time.sleep(60)
        except Exception as e:
            logger.error(f"清理任务出错: {e}")
            time.sleep(60)

# ========================
# 启动服务
# ========================

if __name__ == '__main__':
    threading.Thread(target=cleanup_expired_tasks, daemon=True).start()

    print("🔒 HeaderSense 后端服务器启动中...")
    print("=" * 50)
    print("API端点:")
    print("  POST /api/scan")
    print("  POST /api/scan/quick")
    print("  GET  /api/scan/status/<task_id>")
    print("  GET  /api/health")
    print("  GET  /api/scanners")
    print("=" * 50)
    print("服务器运行在: http://localhost:5000")

    app.run(
        host='localhost',
        port=5000,
        debug=False,
        threaded=True,
        request_handler=WSGIRequestHandler
    )
