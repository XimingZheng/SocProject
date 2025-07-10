export default class HeaderAnalyzer {
    constructor() {
        this.securityHeaders = {
            'x-content-type-options': {
                name: 'X-Content-Type-Options',
                description: 'Prevent MIME type sniffing attacks',
                recommendedValue: 'nosniff',
                riskLevel: 'medium',
                explanation: 'This header prevents browsers from guessing the MIME type, reducing the risk of executing malicious content.',
                fixSuggestion: 'Add X-Content-Type-Options: nosniff to the server response.',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                description: 'Prevent Clickjacking attacks',
                recommendedValue: ['DENY', 'SAMEORIGIN'],
                riskLevel: 'high',
                explanation: 'This header prevents embedding the page in an iframe to mitigate clickjacking.',
                fixSuggestion: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            },
            'content-security-policy': {
                name: 'Content-Security-Policy',
                description: 'Prevent XSS and code injection attacks',
                recommendedValue: null,
                riskLevel: 'high',
                explanation: 'This header defines the resources the page can load to mitigate XSS attacks.',
                fixSuggestion: '配置适当的CSP策略, 例如：default-src \'self\'',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            },
            'strict-transport-security': {
                name: 'Strict-Transport-Security',
                description: 'Enforce HTTPS connections',
                recommendedValue: null,
                riskLevel: 'medium',
                explanation: 'This header enforces HTTPS and prevents man-in-the-middle attacks.',
                fixSuggestion: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
            },
            'x-xss-protection': {
                name: 'X-XSS-Protection',
                description: 'Enable browser XSS protection',
                recommendedValue: '1; mode=block',
                riskLevel: 'low',
                explanation: 'This header enables the browser XSS filter (deprecated in favor of CSP but still useful).',
                fixSuggestion: 'Set X-XSS-Protection: 1; mode=block',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection']
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                description: 'Control referrer information leakage',
                recommendedValue: ['strict-origin-when-cross-origin', 'no-referrer'],
                riskLevel: 'low',
                explanation: 'This header controls how much referrer information is sent to prevent leakage.',
                fixSuggestion: 'Set Referrer-Policy: strict-origin-when-cross-origin',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            }
        };
    }

    async scan(headers) {
        const issues = [];
        let totalScore = 0;
        let maxScore = 0;

        // 添加调试信息
        console.log('[HeaderAnalyzer] 开始扫描，接收到的头部:', headers);
        console.log('[HeaderAnalyzer] 头部键名:', Object.keys(headers));

        // 确保所有头部键名都是小写
        const normalizedHeaders = {};
        Object.keys(headers).forEach(key => {
            normalizedHeaders[key.toLowerCase()] = headers[key];
        });

        console.log('[HeaderAnalyzer] 标准化后的头部:', normalizedHeaders);

        for (const [headerKey, headerConfig] of Object.entries(this.securityHeaders)) {
            maxScore += this.getRiskScore(headerConfig.riskLevel);
            
            // 使用标准化的头部
            const headerValue = normalizedHeaders[headerKey];
            
            // 添加调试信息
            if (headerKey === 'content-security-policy') {
                console.log('[HeaderAnalyzer] CSP 检查:');
                console.log('  - 查找键名:', headerKey);
                console.log('  - 找到值:', headerValue);
                console.log('  - 是否来自 meta:', normalizedHeaders['_meta_csp']);
            }
            
            const issue = this.analyzeHeader(headerKey, headerValue, headerConfig, normalizedHeaders);

            if (issue) {
                issues.push(issue);
            } else {
                totalScore += this.getRiskScore(headerConfig.riskLevel);
            }
        }

        const scorePercentage = maxScore > 0 ? totalScore / maxScore : 0;
        const overallRiskLevel = this.calculateOverallRisk(scorePercentage, issues);

        console.log('[HeaderAnalyzer] 扫描结果:');
        console.log('  - 评分百分比:', scorePercentage);
        console.log('  - 风险等级:', overallRiskLevel);
        console.log('  - 问题数量:', issues.length);
        console.log('  - 问题详情:', issues.map(i => i.header));

        return {
            riskLevel: overallRiskLevel,
            score: Math.round(scorePercentage * 100),
            issues: issues,
            summary: this.generateSummary(issues, overallRiskLevel),
            timestamp: Date.now(),
            debug: {
                originalHeaders: headers,
                normalizedHeaders: normalizedHeaders,
                scoreCalculation: {
                    totalScore,
                    maxScore,
                    scorePercentage
                }
            }
        };
    }

    analyzeHeader(headerKey, headerValue, headerConfig, allHeaders) {
        if (!headerValue) {
            // 特殊处理 CSP：检查是否通过 meta 标签设置
            if (headerKey === 'content-security-policy' && allHeaders['_meta_csp']) {
                return {
                    type: 'info',
                    header: headerConfig.name,
                    description: headerConfig.description + ' (found in meta tag)',
                    riskLevel: 'low', // 降低风险等级，因为通过 meta 标签设置了
                    explanation: headerConfig.explanation + ' 注意：该CSP通过HTML meta标签设置，建议在HTTP头部设置以获得更好的安全性。',
                    fixSuggestion: 'CSP已通过meta标签设置，建议迁移到HTTP响应头以获得更好的安全性和兼容性。',
                    references: headerConfig.references,
                    currentValue: allHeaders['content-security-policy'],
                    source: 'meta'
                };
            }

            return {
                type: 'missing',
                header: headerConfig.name,
                description: headerConfig.description,
                riskLevel: headerConfig.riskLevel,
                explanation: headerConfig.explanation,
                fixSuggestion: headerConfig.fixSuggestion,
                references: headerConfig.references,
                currentValue: null
            };
        }

        const validationResult = this.validateHeaderValue(headerKey, headerValue, headerConfig);
        if (!validationResult.isValid) {
            return {
                type: 'misconfigured',
                header: headerConfig.name,
                description: headerConfig.description,
                riskLevel: headerConfig.riskLevel,
                explanation: headerConfig.explanation,
                fixSuggestion: headerConfig.fixSuggestion,
                references: headerConfig.references,
                currentValue: headerValue,
                issue: validationResult.issue
            };
        }

        return null;
    }

    validateHeaderValue(headerKey, headerValue, headerConfig) {
        switch (headerKey) {
            case 'x-content-type-options':
                return {
                    isValid: headerValue.toLowerCase() === 'nosniff',
                    issue: headerValue.toLowerCase() !== 'nosniff' ? 'Expected value is "nosniff"' : null
                };

            case 'x-frame-options':
                const validFrameOptions = ['DENY', 'SAMEORIGIN'];
                const isValidFrameOption = validFrameOptions.some(option =>
                    headerValue.toUpperCase().includes(option)
                );
                return {
                    isValid: isValidFrameOption,
                    issue: !isValidFrameOption ? 'Expected value is DENY or SAMEORIGIN' : null
                };

            case 'content-security-policy':
                return this.validateCSP(headerValue);

            case 'strict-transport-security':
                const hasMaxAge = /max-age=(\d+)/.exec(headerValue);
                if (!hasMaxAge) {
                    return {
                        isValid: false,
                        issue: 'Missing max-age directive'
                    };
                }

                const maxAge = parseInt(hasMaxAge[1]);
                if (maxAge < 31536000) {
                    return {
                        isValid: false,
                        issue: 'max-age value too small, recommended at least 31536000 (1 year)'
                    };
                }

                return { isValid: true };

            case 'x-xss-protection':
                const validXSSProtection = ['1', '1; mode=block'];
                return {
                    isValid: validXSSProtection.includes(headerValue),
                    issue: !validXSSProtection.includes(headerValue) ? 'Recommended setting is 1; mode=block' : null
                };

            case 'referrer-policy':
                const validReferrerPolicies = [
                    'no-referrer',
                    'no-referrer-when-downgrade',
                    'origin',
                    'origin-when-cross-origin',
                    'same-origin',
                    'strict-origin',
                    'strict-origin-when-cross-origin',
                    'unsafe-url'
                ];
                return {
                    isValid: validReferrerPolicies.includes(headerValue),
                    issue: !validReferrerPolicies.includes(headerValue) ? 'Invalid Referrer-Policy value' : null
                };

            default:
                return { isValid: true };
        }
    }

    validateCSP(cspValue) {
        console.log('[HeaderAnalyzer] 验证 CSP 值:', cspValue);
        
        if (!cspValue || cspValue.trim() === '') {
            return {
                isValid: false,
                issue: 'CSP value is empty'
            };
        }

        const cspLower = cspValue.toLowerCase();
        const directives = cspValue.split(';').map(d => d.trim()).filter(d => d);
        
        console.log('[HeaderAnalyzer] CSP 指令:', directives);

        // 检查关键指令
        const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
        const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
        const hasObjectSrc = directives.some(d => d.startsWith('object-src'));
        
        // 检查不安全的指令
        const hasUnsafeInline = cspLower.includes("'unsafe-inline'");
        const hasUnsafeEval = cspLower.includes("'unsafe-eval'");
        const hasWildcard = cspLower.includes('*') && !cspLower.includes("'self'");

        // 评估 CSP 强度
        let issues = [];
        
        if (!hasDefaultSrc && !hasScriptSrc) {
            issues.push('Missing default-src or script-src directive');
        }
        
        if (hasUnsafeInline) {
            issues.push("Contains 'unsafe-inline' directive, which reduces security");
        }
        
        if (hasUnsafeEval) {
            issues.push("Contains 'unsafe-eval' directive, which reduces security");
        }
        
        if (hasWildcard) {
            issues.push("Contains wildcard (*) without proper restrictions");
        }

        // 检查常见的弱 CSP 配置
        if (cspLower.includes('unsafe-inline') && cspLower.includes('unsafe-eval')) {
            issues.push('CSP contains both unsafe-inline and unsafe-eval, providing minimal protection');
        }

        console.log('[HeaderAnalyzer] CSP 验证结果:', {
            hasDefaultSrc,
            hasScriptSrc,
            hasUnsafeInline,
            hasUnsafeEval,
            hasWildcard,
            issues
        });

        if (issues.length > 0) {
            return {
                isValid: false,
                issue: issues.join('; ')
            };
        }

        return { isValid: true };
    }

    getRiskScore(riskLevel) {
        switch (riskLevel) {
            case 'high': return 10;
            case 'medium': return 6;
            case 'low': return 3;
            default: return 0;
        }
    }

    calculateOverallRisk(scorePercentage, issues) {
        const highRiskIssues = issues.filter(issue => issue.riskLevel === 'high').length;
        const mediumRiskIssues = issues.filter(issue => issue.riskLevel === 'medium').length;

        // 更严格的风险评估
        if (highRiskIssues >= 2 || scorePercentage < 0.3) {
            return 'high';
        } else if (highRiskIssues >= 1 || mediumRiskIssues >= 2 || scorePercentage < 0.6) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    generateSummary(issues, overallRiskLevel) {
        if (issues.length === 0) {
            return '✅ Security headers are properly configured for this page';
        }

        const highRiskCount = issues.filter(issue => issue.riskLevel === 'high').length;
        const mediumRiskCount = issues.filter(issue => issue.riskLevel === 'medium').length;
        const lowRiskCount = issues.filter(issue => issue.riskLevel === 'low').length;

        let summary = '';
        if (highRiskCount > 0) {
            summary += `Detected ${highRiskCount} high-risk issues`;
        }
        if (mediumRiskCount > 0) {
            summary += `${summary ? ', ' : 'Detected '}${mediumRiskCount} medium-risk issues`;
        }
        if (lowRiskCount > 0) {
            summary += `${summary ? ', ' : 'Detected '}${lowRiskCount} low-risk issues`;
        }

        return summary;
    }
}