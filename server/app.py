#!/usr/bin/env python3
"""
Flask backend security scanning server
Provides multithreaded scanning service for Chrome extension
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
# Basic configuration
# ========================

app = Flask(__name__)
CORS(app)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Global task storage
scan_tasks: Dict[str, Any] = {}
task_results: Dict[str, Any] = {}

# ========================
# API Routes
# ========================

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})

        if not url:
            return jsonify({'error': 'Missing URL parameter'}), 400

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
                logger.error(f"Scan task {task_id} failed: {e}")
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

        return jsonify({'task_id': task_id, 'status': 'started', 'message': 'Scan task started'})

    except Exception as e:
        logger.error(f"Failed to start scan task: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/status/<task_id>', methods=['GET'])
def get_scan_status(task_id):
    try:
        if task_id not in task_results:
            return jsonify({'error': 'Task not found'}), 404

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
        logger.error(f"Failed to get task status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/quick', methods=['POST'])
def quick_scan():
    try:
        data = request.get_json()
        url = data.get('url')
        headers_data = data.get('headers', {})

        if not url:
            return jsonify({'error': 'Missing URL parameter'}), 400

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

        # 馃敟 鍏抽敭淇敼锛氫娇鐢╬enalty-based璇勫垎璁＄畻瀹夊叏鍒嗘暟
        security_score = calculate_penalty_based_score(results, scanner)

        # 馃敟 鍏抽敭淇敼锛氬熀浜庡垎鏁拌?屼笉鏄棶棰樻暟閲忕‘瀹氶闄╃瓑绾?
        overall_risk = determine_score_based_risk(security_score)

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
            'summary': f"{len(results)} HTTP header security issues found" if results else "HTTP headers are properly configured"
        })

    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        return jsonify({'error': str(e)}), 500


def calculate_penalty_based_score(results, scanner):
    """馃敟 鍏抽敭锛氳绠楀熀浜巔enalty鐨勫畨鍏ㄨ瘎鍒?"""
    total_penalty = 0
    max_possible_penalty = scanner.get_max_possible_penalty()
    
    print(f"[QuickScan] 馃搳 鏈?澶у彲鑳芥儵缃氬垎: {max_possible_penalty}")
    
    # 璁＄畻瀹為檯鎯╃綒
    for result in results:
        penalty_score = 0
        
        # 浠庣粨鏋滅殑details涓幏鍙杙enalty_score
        if result.details and 'penalty_score' in result.details:
            penalty_score = result.details['penalty_score']
            print(f"[QuickScan] 鈿狅笍 {result.title}: {penalty_score}鍒嗘儵缃?")
        else:
            # 鍚庡璁＄畻鏂规硶
            if 'Header' in result.vulnerability_type:
                if result.vulnerability_type == 'Missing Security Header':
                    if 'CSP' in result.title or 'Content-Security-Policy' in result.title:
                        penalty_score = 25
                    elif result.risk_level == 'high':
                        penalty_score = 10
                    elif result.risk_level == 'medium':
                        penalty_score = 6
                    else:
                        penalty_score = 3
                elif result.vulnerability_type == 'Misconfigured Security Header':
                    if 'CSP' in result.title or 'Content-Security-Policy' in result.title:
                        severity = result.details.get('severity', 'moderate') if result.details else 'moderate'
                        if severity == 'critical':
                            penalty_score = 12
                        elif severity == 'major':
                            penalty_score = 8
                        elif severity == 'moderate':
                            penalty_score = 5
                        else:
                            penalty_score = 2
                    else:
                        if result.risk_level == 'high':
                            penalty_score = 5
                        elif result.risk_level == 'medium':
                            penalty_score = 3
                        else:
                            penalty_score = 1
                elif result.vulnerability_type == 'CSP Set via Meta Tag':
                    penalty_score = 4
            
            print(f"[QuickScan] 鈿狅笍 {result.title}: {penalty_score}鍒嗘儵缃? (鍚庡璁＄畻)")
        
        total_penalty += penalty_score
    
    print(f"[QuickScan] 馃搳 鎬绘儵缃氬垎: {total_penalty}/{max_possible_penalty}")
    
    # 浣跨敤涓庡墠绔浉鍚岀殑璇勫垎鍏紡
    if max_possible_penalty > 0:
        penalty_percentage = total_penalty / max_possible_penalty
        score = max(0, round(100 * (1 - penalty_percentage)))
    else:
        score = max(0, 100 - total_penalty)
    
    print(f"[QuickScan] 馃幆 鏈?缁堣瘎鍒?: {score}/100")
    return score


def determine_score_based_risk(security_score: int) -> str:
    """馃敟 鍏抽敭淇敼锛氱函绮瑰熀浜庡垎鏁扮‘瀹氭暣浣撻闄╃瓑绾?"""
    print(f"[QuickScan] 馃幆 鍩轰簬鍒嗘暟璁＄畻椋庨櫓绛夌骇: score={security_score}")
    
    # 绾补鍩轰簬鍒嗘暟鐨勯闄╃瓑绾у垽鏂紝涓庡墠绔繚鎸佷竴鑷?
    if security_score < 40:
        print('[QuickScan] 馃敶 椋庨櫓绛夌骇: high (鍒嗘暟 < 40)')
        return 'high'
    elif security_score < 70:
        print('[QuickScan] 馃煚 椋庨櫓绛夌骇: medium (鍒嗘暟 < 70)')
        return 'medium'
    else:
        print('[QuickScan] 馃煝 椋庨櫓绛夌骇: low (鍒嗘暟 >= 70)')
        return 'low'


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
            'description': 'Detects HTTP response header security misconfigurations',
            'vulnerability_types': ['Missing Security Header', 'Misconfigured Security Header']
        },
        {
            'name': 'XSS Scanner',
            'description': 'Detects Cross-Site Scripting vulnerabilities',
            'vulnerability_types': ['Cross-Site Scripting (XSS)']
        },
        {
            'name': 'SQL Injection Scanner',
            'description': 'Detects SQL injection vulnerabilities',
            'vulnerability_types': ['SQL Injection']
        },
        {
            'name': 'SSL Scanner',
            'description': 'Detects SSL/TLS configuration issues',
            'vulnerability_types': ['Insecure Protocol']
        }
    ]

    return jsonify({
        'scanners': scanners_info,
        'total_scanners': len(scanners_info)
    })

# ========================
# Expired task cleanup
# ========================

def cleanup_expired_tasks():
    while True:
        try:
            current_time = time.time()
            expired = [task_id for task_id, info in scan_tasks.items()
                       if current_time - info.get('start_time', current_time) > 600]
            for task_id in expired:
                logger.info(f"Cleaning up expired task: {task_id}")
                scan_tasks.pop(task_id, None)
                task_results.pop(task_id, None)
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error during task cleanup: {e}")
            time.sleep(60)

# ========================
# Start server
# ========================

if __name__ == '__main__':
    threading.Thread(target=cleanup_expired_tasks, daemon=True).start()

    print("馃敀 HeaderSense backend server starting...")
    print("=" * 50)
    print("API Endpoints:")
    print("  POST /api/scan")
    print("  POST /api/scan/quick")
    print("  GET  /api/scan/status/<task_id>")
    print("  GET  /api/health")
    print("  GET  /api/scanners")
    print("=" * 50)
    print("Server running at: http://localhost:5000")

    app.run(
        host='localhost',
        port=5000,
        debug=False,
        threaded=True,
        request_handler=WSGIRequestHandler
    )