# #!/usr/bin/env python3
# """
# Flask后端安全扫描服务器
# 为Chrome扩展提供多线程安全扫描服务
# """

# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import asyncio
# import threading
# import time
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from typing import Dict, List, Optional, Tuple, Any
# from dataclasses import dataclass, asdict
# from abc import ABC, abstractmethod
# from urllib.parse import urljoin, urlparse
# from datetime import datetime
# import uuid
# from werkzeug.serving import WSGIRequestHandler

# # Flask API路由
# @app.route('/api/scan', methods=['POST'])
# def start_scan():
#     """启动扫描任务"""
#     try:
#         data = request.get_json()
#         url = data.get('url')
#         headers_data = data.get('headers', {})
        
#         if not url:
#             return jsonify({'error': '缺少URL参数'}), 400
        
#         # 生成任务ID
#         task_id = str(uuid.uuid4())
        
#         # 创建扫描任务
#         def run_scan_task():
#             try:
#                 loop = asyncio.new_event_loop()
#                 asyncio.set_event_loop(loop)
                
#                 scanner_manager = ThreadSafeScannerManager()
#                 result = loop.run_until_complete(
#                     scanner_manager.scan_website(url, headers_data)
#                 )
                
#                 task_results[task_id] = {
#                     'status': 'completed',
#                     'result': result
#                 }
                
#                 loop.close()
                
#             except Exception as e:
#                 logger.error(f"扫描任务 {task_id} 失败: {e}")
#                 task_results[task_id] = {
#                     'status': 'failed',
#                     'error': str(e)
#                 }
        
#         # 在后台线程中运行扫描
#         scan_thread = threading.Thread(target=run_scan_task)
#         scan_thread.daemon = True
#         scan_thread.start()
        
#         # 存储任务信息
#         scan_tasks[task_id] = {
#             'status': 'running',
#             'url': url,
#             'start_time': time.time(),
#             'thread': scan_thread
#         }
        
#         task_results[task_id] = {'status': 'running'}
        
#         return jsonify({
#             'task_id': task_id,
#             'status': 'started',
#             'message': '扫描任务已启动'
#         })
        
#     except Exception as e:
#         logger.error(f"启动扫描任务失败: {e}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/scan/status/<task_id>', methods=['GET'])
# def get_scan_status(task_id):
#     """获取扫描任务状态"""
#     try:
#         if task_id not in task_results:
#             return jsonify({'error': '任务不存在'}), 404
        
#         task_result = task_results[task_id]
#         task_info = scan_tasks.get(task_id, {})
        
#         response = {
#             'task_id': task_id,
#             'status': task_result['status']
#         }
        
#         if task_result['status'] == 'completed':
#             response['result'] = task_result['result']
#             # 清理完成的任务
#             if task_id in scan_tasks:
#                 del scan_tasks[task_id]
#             del task_results[task_id]
#         elif task_result['status'] == 'failed':
#             response['error'] = task_result['error']
#             # 清理失败的任务
#             if task_id in scan_tasks:
#                 del scan_tasks[task_id]
#             del task_results[task_id]
#         elif task_result['status'] == 'running':
#             response['elapsed_time'] = time.time() - task_info.get('start_time', time.time())
        
#         return jsonify(response)
        
#     except Exception as e:
#         logger.error(f"获取任务状态失败: {e}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/scan/quick', methods=['POST'])
# def quick_scan():
#     """快速扫描（仅响应头检查）"""
#     try:
#         data = request.get_json()
#         url = data.get('url')
#         headers_data = data.get('headers', {})
        
#         if not url:
#             return jsonify({'error': '缺少URL参数'}), 400
        
#         # 只运行Header扫描器进行快速检查
#         scanner = HeaderScanner()
        
#         async def quick_scan_task():
#             response_data = {
#                 'headers': headers_data,
#                 'content': '',
#                 'status': 200,
#                 'url': url
#             }
#             return await scanner.scan(None, url, response_data)
        
#         # 运行快速扫描
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)
#         results = loop.run_until_complete(quick_scan_task())
#         loop.close()
        
#         # 生成简化报告
#         high_risk = [r for r in results if r.risk_level == 'high']
#         medium_risk = [r for r in results if r.risk_level == 'medium']
#         low_risk = [r for r in results if r.risk_level == 'low']
        
#         security_score = max(0, 100 - (len(high_risk) * 20 + len(medium_risk) * 10 + len(low_risk) * 5))
        
#         if len(high_risk) >= 2 or security_score < 40:
#             overall_risk = 'high'
#         elif len(high_risk) >= 1 or len(medium_risk) >= 2 or security_score < 70:
#             overall_risk = 'medium'
#         else:
#             overall_risk = 'low'
        
#         return jsonify({
#             'url': url,
#             'scan_type': 'quick',
#             'security_score': security_score,
#             'risk_level': overall_risk,
#             'total_issues': len(results),
#             'statistics': {
#                 'high_risk': len(high_risk),
#                 'medium_risk': len(medium_risk),
#                 'low_risk': len(low_risk)
#             },
#             'issues': [result.to_dict() for result in results],
#             'summary': f"发现 {len(results)} 个响应头安全问题" if results else "响应头配置良好"
#         })
        
#     except Exception as e:
#         logger.error(f"快速扫描失败: {e}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/health', methods=['GET'])
# def health_check():
#     """健康检查"""
#     return jsonify({
#         'status': 'healthy',
#         'timestamp': datetime.now().isoformat(),
#         'version': '1.0.0',
#         'active_tasks': len(scan_tasks)
#     })

# @app.route('/api/scanners', methods=['GET'])
# def get_available_scanners():
#     """获取可用的扫描器列表"""
#     scanners_info = [
#         {
#             'name': 'Header Scanner',
#             'description': '检测HTTP安全响应头配置',
#             'vulnerability_types': ['Missing Security Header', 'Misconfigured Security Header']
#         },
#         {
#             'name': 'XSS Scanner',
#             'description': '检测跨站脚本攻击漏洞',
#             'vulnerability_types': ['Cross-Site Scripting (XSS)']
#         },
#         {
#             'name': 'SQL Injection Scanner',
#             'description': '检测SQL注入漏洞',
#             'vulnerability_types': ['SQL Injection']
#         },
#         {
#             'name': 'SSL Scanner',
#             'description': '检测SSL/TLS配置问题',
#             'vulnerability_types': ['Insecure Protocol']
#         }
#     ]
    
#     return jsonify({
#         'scanners': scanners_info,
#         'total_scanners': len(scanners_info)
#     })

# # 清理过期任务的后台线程
# def cleanup_expired_tasks():
#     """清理过期的任务"""
#     while True:
#         try:
#             current_time = time.time()
#             expired_tasks = []
            
#             for task_id, task_info in scan_tasks.items():
#                 # 清理运行超过10分钟的任务
#                 if current_time - task_info.get('start_time', current_time) > 600:
#                     expired_tasks.append(task_id)
            
#             for task_id in expired_tasks:
#                 logger.info(f"清理过期任务: {task_id}")
#                 if task_id in scan_tasks:
#                     del scan_tasks[task_id]
#                 if task_id in task_results:
#                     del task_results[task_id]
            
#             time.sleep(60)  # 每分钟清理一次
            
#         except Exception as e:
#             logger.error(f"清理任务时出错: {e}")
#             time.sleep(60)

# if __name__ == '__main__':
#     # 启动清理线程
#     cleanup_thread = threading.Thread(target=cleanup_expired_tasks)
#     cleanup_thread.daemon = True
#     cleanup_thread.start()
    
#     print("🔒 HeaderSense 后端服务器启动中...")
#     print("=" * 50)
#     print("API端点:")
#     print("  POST /api/scan - 启动完整扫描")
#     print("  POST /api/scan/quick - 快速响应头扫描")
#     print("  GET  /api/scan/status/<task_id> - 获取扫描状态")
#     print("  GET  /api/health - 健康检查")
#     print("  GET  /api/scanners - 获取可用扫描器")
#     print("=" * 50)
#     print("服务器运行在: http://localhost:5000")
#     print("Chrome扩展可以通过API与后端通信")
    
#     app.run(
#         host='localhost',
#         port=5000,
#         debug=False,
#         threaded=True,
#         request_handler=QuietWSGIRequestHandler
#     )