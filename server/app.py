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
            'summary': f"{len(results)} HTTP header security issues found" if results else "HTTP headers are properly configured"
        })

    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
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

    print("🔒 HeaderSense backend server starting...")
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
