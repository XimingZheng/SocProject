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
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
                // 评分权重
                missingPenalty: 6,
                misconfiguredPenalty: 3
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                description: 'Prevent Clickjacking attacks',
                recommendedValue: ['DENY', 'SAMEORIGIN'],
                riskLevel: 'high',
                explanation: 'This header prevents embedding the page in an iframe to mitigate clickjacking.',
                fixSuggestion: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
                missingPenalty: 10,
                misconfiguredPenalty: 5
            },
            'content-security-policy': {
                name: 'Content-Security-Policy',
                description: 'Prevent XSS and code injection attacks',
                recommendedValue: null,
                riskLevel: 'high',
                explanation: 'This header defines the resources the page can load to mitigate XSS attacks.',
                fixSuggestion: '配置适当的CSP策略, 例如：default-src \'self\'',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
                // CSP特殊评分：缺失惩罚大，配置不当惩罚相对较小
                missingPenalty: 15,      // 缺失惩罚很大
                misconfiguredPenalty: 5, // 配置不当惩罚较小
                metaTagPenalty: 2       // 通过meta标签设置的轻微惩罚
            },
            'strict-transport-security': {
                name: 'Strict-Transport-Security',
                description: 'Enforce HTTPS connections',
                recommendedValue: null,
                riskLevel: 'medium',
                explanation: 'This header enforces HTTPS and prevents man-in-the-middle attacks.',
                fixSuggestion: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
                missingPenalty: 6,
                misconfiguredPenalty: 3
            },
            'x-xss-protection': {
                name: 'X-XSS-Protection',
                description: 'Enable browser XSS protection',
                recommendedValue: '1; mode=block',
                riskLevel: 'low',
                explanation: 'This header enables the browser XSS filter (deprecated in favor of CSP but still useful).',
                fixSuggestion: 'Set X-XSS-Protection: 1; mode=block',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection'],
                missingPenalty: 3,
                misconfiguredPenalty: 1
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                description: 'Control referrer information leakage',
                recommendedValue: ['strict-origin-when-cross-origin', 'no-referrer'],
                riskLevel: 'low',
                explanation: 'This header controls how much referrer information is sent to prevent leakage.',
                fixSuggestion: 'Set Referrer-Policy: strict-origin-when-cross-origin',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
                missingPenalty: 3,
                misconfiguredPenalty: 1
            }
        };
    }

    async scan(headers) {
        const issues = [];
        let totalPenalty = 0;
        let maxPossiblePenalty = 0;

        // 添加调试信息
        console.log('[HeaderAnalyzer] 开始扫描，接收到的头部:', headers);

        // 确保所有头部键名都是小写
        const normalizedHeaders = {};
        Object.keys(headers).forEach(key => {
            normalizedHeaders[key.toLowerCase()] = headers[key];
        });

        console.log('[HeaderAnalyzer] 标准化后的头部:', normalizedHeaders);

        // 计算最大可能惩罚分（用于评分计算）
        Object.values(this.securityHeaders).forEach(config => {
            maxPossiblePenalty += config.missingPenalty;
        });

        for (const [headerKey, headerConfig] of Object.entries(this.securityHeaders)) {
            const headerValue = normalizedHeaders[headerKey];
            
            // CSP特殊调试信息
            if (headerKey === 'content-security-policy') {
                console.log('[HeaderAnalyzer] CSP 详细检查:');
                console.log('  - 查找键名:', headerKey);
                console.log('  - 找到值:', headerValue);
                console.log('  - 是否来自 meta:', normalizedHeaders['_meta_csp']);
                console.log('  - 原始头部中的CSP相关键:', Object.keys(headers).filter(k => k.toLowerCase().includes('csp') || k.toLowerCase().includes('content-security')));
            }
            
            const analysisResult = this.analyzeHeaderWithScoring(headerKey, headerValue, headerConfig, normalizedHeaders);
            
            if (analysisResult.issue) {
                issues.push(analysisResult.issue);
            }
            
            totalPenalty += analysisResult.penalty;
        }

        // 计算评分：100 - (惩罚分 / 最大惩罚分 * 100)
        const score = Math.max(0, Math.round(100 - (totalPenalty / maxPossiblePenalty * 100)));
        const overallRiskLevel = this.calculateOverallRiskWithScoring(score, issues);

        console.log('[HeaderAnalyzer] 评分详情:');
        console.log('  - 总惩罚分:', totalPenalty);
        console.log('  - 最大惩罚分:', maxPossiblePenalty);
        console.log('  - 计算得分:', score);
        console.log('  - 风险等级:', overallRiskLevel);

        return {
            riskLevel: overallRiskLevel,
            score: score,
            issues: issues,
            summary: this.generateSummary(issues, overallRiskLevel),
            timestamp: Date.now(),
            debug: {
                originalHeaders: headers,
                normalizedHeaders: normalizedHeaders,
                scoreCalculation: {
                    totalPenalty,
                    maxPossiblePenalty,
                    penaltyPercentage: (totalPenalty / maxPossiblePenalty * 100).toFixed(1)
                },
                issueBreakdown: this.generateIssueBreakdown(issues)
            }
        };
    }

    analyzeHeaderWithScoring(headerKey, headerValue, headerConfig, allHeaders) {
        let penalty = 0;
        let issue = null;

        if (!headerValue) {
            // 特殊处理 CSP：检查是否通过 meta 标签设置
            if (headerKey === 'content-security-policy' && allHeaders['_meta_csp']) {
                penalty = headerConfig.metaTagPenalty || 2;
                issue = {
                    type: 'meta-tag',
                    header: headerConfig.name,
                    description: headerConfig.description + ' (found in meta tag)',
                    riskLevel: 'low',
                    explanation: headerConfig.explanation + ' 注意：该CSP通过HTML meta标签设置，建议在HTTP头部设置以获得更好的安全性。',
                    fixSuggestion: 'CSP已通过meta标签设置，建议迁移到HTTP响应头以获得更好的安全性和兼容性。',
                    references: headerConfig.references,
                    currentValue: allHeaders['content-security-policy'],
                    source: 'meta',
                    penalty: penalty
                };
            } else {
                // 头部完全缺失
                penalty = headerConfig.missingPenalty;
                issue = {
                    type: 'missing',
                    header: headerConfig.name,
                    description: headerConfig.description,
                    riskLevel: headerConfig.riskLevel,
                    explanation: headerConfig.explanation,
                    fixSuggestion: headerConfig.fixSuggestion,
                    references: headerConfig.references,
                    currentValue: null,
                    penalty: penalty
                };
            }
        } else {
            // 头部存在，检查配置是否正确
            const validationResult = this.validateHeaderValue(headerKey, headerValue, headerConfig);
            if (!validationResult.isValid) {
                // 头部配置不当
                penalty = headerConfig.misconfiguredPenalty;
                issue = {
                    type: 'misconfigured',
                    header: headerConfig.name,
                    description: headerConfig.description,
                    riskLevel: this.reducedRiskLevel(headerConfig.riskLevel), // 降低风险等级
                    explanation: headerConfig.explanation,
                    fixSuggestion: headerConfig.fixSuggestion,
                    references: headerConfig.references,
                    currentValue: headerValue,
                    issue: validationResult.issue,
                    penalty: penalty
                };
            }
            // 如果配置正确，penalty保持为0，issue保持为null
        }

        return { penalty, issue };
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

        // 评估 CSP 强度 - 使用分级验证
        let issues = [];
        let severity = 'minor'; // minor, major, critical
        
        // 关键缺失（严重问题）
        if (!hasDefaultSrc && !hasScriptSrc) {
            issues.push('Missing default-src or script-src directive');
            severity = 'major';
        }
        
        // 不安全指令（中等问题）
        if (hasUnsafeInline && hasUnsafeEval) {
            issues.push('CSP contains both unsafe-inline and unsafe-eval, providing minimal protection');
            severity = 'major';
        } else if (hasUnsafeInline) {
            issues.push("Contains 'unsafe-inline' directive, which reduces security");
            if (severity === 'minor') severity = 'moderate';
        } else if (hasUnsafeEval) {
            issues.push("Contains 'unsafe-eval' directive, which reduces security");
            if (severity === 'minor') severity = 'moderate';
        }
        
        // 通配符问题（轻微问题）
        if (hasWildcard) {
            issues.push('Contains wildcard (*) without proper restrictions');
            if (severity === 'minor') severity = 'moderate';
        }

        console.log('[HeaderAnalyzer] CSP 验证结果:', {
            hasDefaultSrc,
            hasScriptSrc,
            hasUnsafeInline,
            hasUnsafeEval,
            hasWildcard,
            issues,
            severity
        });

        if (issues.length > 0) {
            return {
                isValid: false,
                issue: issues.join('; '),
                severity: severity
            };
        }

        return { isValid: true };
    }

    reducedRiskLevel(originalRiskLevel) {
        // 对于配置不当的头部，降低一个等级的风险
        switch (originalRiskLevel) {
            case 'high': return 'medium';
            case 'medium': return 'low';
            case 'low': return 'low';
            default: return originalRiskLevel;
        }
    }

    calculateOverallRiskWithScoring(score, issues) {
        const highRiskIssues = issues.filter(issue => issue.riskLevel === 'high').length;
        const mediumRiskIssues = issues.filter(issue => issue.riskLevel === 'medium').length;
        const missingCSP = issues.some(issue => issue.type === 'missing' && issue.header === 'Content-Security-Policy');

        // 基于评分的风险等级判断
        if (score < 40 || highRiskIssues >= 2 || missingCSP) {
            return 'high';
        } else if (score < 70 || highRiskIssues >= 1 || mediumRiskIssues >= 2) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    generateSummary(issues, overallRiskLevel) {
        if (issues.length === 0) {
            return '✅ Security headers are properly configured for this page';
        }

        const missingCount = issues.filter(issue => issue.type === 'missing').length;
        const misconfiguredCount = issues.filter(issue => issue.type === 'misconfigured').length;
        const metaTagCount = issues.filter(issue => issue.type === 'meta-tag').length;

        let summary = [];
        
        if (missingCount > 0) {
            summary.push(`${missingCount} missing headers`);
        }
        if (misconfiguredCount > 0) {
            summary.push(`${misconfiguredCount} misconfigured headers`);
        }
        if (metaTagCount > 0) {
            summary.push(`${metaTagCount} headers set via meta tags`);
        }

        return `Detected ${summary.join(', ')}`;
    }

    generateIssueBreakdown(issues) {
        const breakdown = {
            missing: issues.filter(i => i.type === 'missing').length,
            misconfigured: issues.filter(i => i.type === 'misconfigured').length,
            metaTag: issues.filter(i => i.type === 'meta-tag').length,
            totalPenalty: issues.reduce((sum, issue) => sum + (issue.penalty || 0), 0)
        };

        const penaltyBreakdown = issues.map(issue => ({
            header: issue.header,
            type: issue.type,
            penalty: issue.penalty || 0,
            riskLevel: issue.riskLevel
        }));

        return { breakdown, penaltyBreakdown };
    }
}