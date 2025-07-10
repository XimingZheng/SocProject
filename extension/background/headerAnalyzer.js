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
                // 🔥 关键修复：CSP特殊评分配置
                missingPenalty: 25,         // 增加CSP缺失惩罚
                misconfiguredPenalty: 8,    // 一般配置错误
                weakCSPPenalty: 5,          // 弱CSP配置
                incompleteCSPPenalty: 12,   // 不完整CSP配置
                metaTagPenalty: 4           // Meta标签设置
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
        console.log('[HeaderAnalyzer] 🔍 开始扫描，接收到的头部:', headers);

        // 确保所有头部键名都是小写
        const normalizedHeaders = {};
        Object.keys(headers).forEach(key => {
            normalizedHeaders[key.toLowerCase()] = headers[key];
        });

        console.log('[HeaderAnalyzer] 📝 标准化后的头部:', normalizedHeaders);

        // 🔥 修复：计算最大可能惩罚分时包含所有惩罚类型
        Object.values(this.securityHeaders).forEach(config => {
            maxPossiblePenalty += config.missingPenalty;
        });

        console.log('[HeaderAnalyzer] 📊 最大可能惩罚分:', maxPossiblePenalty);

        for (const [headerKey, headerConfig] of Object.entries(this.securityHeaders)) {
            const headerValue = normalizedHeaders[headerKey];
            
            // CSP特殊调试信息
            if (headerKey === 'content-security-policy') {
                console.log('[HeaderAnalyzer] 🛡️ CSP 详细检查:');
                console.log('  - 查找键名:', headerKey);
                console.log('  - 找到值:', headerValue);
                console.log('  - 是否来自 meta:', normalizedHeaders['_meta_csp']);
                console.log('  - CSP配置:', headerConfig);
            }
            
            const analysisResult = this.analyzeHeaderWithScoring(headerKey, headerValue, headerConfig, normalizedHeaders);
            
            if (analysisResult.issue) {
                issues.push(analysisResult.issue);
            }
            
            totalPenalty += analysisResult.penalty;
            
            // 调试信息
            if (analysisResult.penalty > 0) {
                console.log(`[HeaderAnalyzer] ⚠️  ${headerKey} 惩罚: ${analysisResult.penalty}分`);
            }
        }

        // 🔥 修复：调整评分计算公式，确保差异更明显
        const penaltyPercentage = maxPossiblePenalty > 0 ? (totalPenalty / maxPossiblePenalty) : 0;
        const score = Math.max(0, Math.round(100 * (1 - penaltyPercentage)));
        const overallRiskLevel = this.calculateOverallRiskWithScoring(score, issues);

        console.log('[HeaderAnalyzer] 📈 评分详情:');
        console.log('  - 总惩罚分:', totalPenalty);
        console.log('  - 最大惩罚分:', maxPossiblePenalty);
        console.log('  - 惩罚百分比:', (penaltyPercentage * 100).toFixed(1) + '%');
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
                    penaltyPercentage: (penaltyPercentage * 100).toFixed(1)
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
                penalty = headerConfig.metaTagPenalty || 4;
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
                console.log(`[HeaderAnalyzer] 📋 CSP通过meta标签设置，惩罚: ${penalty}分`);
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
                console.log(`[HeaderAnalyzer] ❌ ${headerKey} 缺失，惩罚: ${penalty}分`);
            }
        } else {
            // 头部存在，检查配置是否正确
            const validationResult = this.validateHeaderValue(headerKey, headerValue, headerConfig);
            if (!validationResult.isValid) {
                // 🔥 关键修复：确保CSP使用差异化惩罚
                if (headerKey === 'content-security-policy') {
                    penalty = this.calculateCSPPenalty(headerValue, headerConfig, validationResult);
                    console.log(`[HeaderAnalyzer] 🔧 CSP配置不当，严重程度: ${validationResult.severity}, 惩罚: ${penalty}分`);
                } else {
                    penalty = headerConfig.misconfiguredPenalty;
                    console.log(`[HeaderAnalyzer] ⚙️ ${headerKey} 配置不当，惩罚: ${penalty}分`);
                }
                
                issue = {
                    type: 'misconfigured',
                    header: headerConfig.name,
                    description: headerConfig.description,
                    riskLevel: this.reducedRiskLevel(headerConfig.riskLevel),
                    explanation: headerConfig.explanation,
                    fixSuggestion: headerConfig.fixSuggestion,
                    references: headerConfig.references,
                    currentValue: headerValue,
                    issue: validationResult.issue,
                    penalty: penalty,
                    severity: validationResult.severity || 'moderate'
                };
            } else {
                console.log(`[HeaderAnalyzer] ✅ ${headerKey} 配置正确`);
            }
        }

        return { penalty, issue };
    }

    calculateCSPPenalty(cspValue, headerConfig, validationResult) {
        // 🔥 关键修复：根据CSP问题的严重程度分配不同惩罚
        const severity = validationResult.severity || 'moderate';
        
        let penalty;
        switch (severity) {
            case 'critical':
                penalty = headerConfig.incompleteCSPPenalty || 12;   // 严重配置问题
                break;
            case 'major':
                penalty = headerConfig.misconfiguredPenalty || 8;    // 重大配置问题
                break;
            case 'moderate':
                penalty = headerConfig.weakCSPPenalty || 5;          // 中等配置问题
                break;
            case 'minor':
                penalty = 2;                                         // 轻微配置问题
                break;
            default:
                penalty = headerConfig.misconfiguredPenalty || 8;
                break;
        }
        
        console.log(`[HeaderAnalyzer] 🎯 CSP惩罚计算: 严重程度=${severity}, 惩罚=${penalty}分`);
        return penalty;
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
        console.log('[HeaderAnalyzer] 🛡️ 验证 CSP 值:', cspValue);
        
        if (!cspValue || cspValue.trim() === '') {
            return {
                isValid: false,
                issue: 'CSP value is empty',
                severity: 'critical'
            };
        }

        const cspLower = cspValue.toLowerCase();
        const directives = cspValue.split(';').map(d => d.trim()).filter(d => d);
        
        console.log('[HeaderAnalyzer] 📋 CSP 指令:', directives);

        // 检查关键指令
        const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
        const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
        const hasObjectSrc = directives.some(d => d.startsWith('object-src'));
        
        // 检查不安全的指令
        const hasUnsafeInline = cspLower.includes("'unsafe-inline'");
        const hasUnsafeEval = cspLower.includes("'unsafe-eval'");
        const hasWildcard = cspLower.includes('*') && !cspLower.includes("'self'");

        // 🔥 关键修复：使用更严格的CSP验证逻辑
        let issues = [];
        let severity = 'minor';
        
        // 关键缺失（严重问题）
        if (!hasDefaultSrc && !hasScriptSrc) {
            issues.push('Missing default-src or script-src directive');
            severity = 'critical';
        } else if (!hasDefaultSrc) {
            issues.push('Missing default-src directive');
            severity = 'major';
        }
        
        // 极不安全组合（严重问题）
        if (hasUnsafeInline && hasUnsafeEval && hasWildcard) {
            issues.push('CSP contains unsafe-inline, unsafe-eval, and wildcard - provides minimal protection');
            severity = 'critical';
        }
        // 不安全指令组合（重大问题）
        else if (hasUnsafeInline && hasUnsafeEval) {
            issues.push('CSP contains both unsafe-inline and unsafe-eval, reducing security significantly');
            if (severity === 'minor') severity = 'major';
        }
        // 单个不安全指令（中等问题）
        else if (hasUnsafeInline) {
            issues.push("Contains 'unsafe-inline' directive, which reduces security");
            if (severity === 'minor') severity = 'moderate';
        } else if (hasUnsafeEval) {
            issues.push("Contains 'unsafe-eval' directive, which reduces security");
            if (severity === 'minor') severity = 'moderate';
        }
        
        // 通配符问题（轻微到中等问题）
        if (hasWildcard) {
            issues.push('Contains wildcard (*) without proper restrictions');
            if (severity === 'minor') severity = 'moderate';
        }

        console.log('[HeaderAnalyzer] 🔍 CSP 验证结果:', {
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
        const criticalCSP = issues.some(issue => issue.severity === 'critical' && issue.header === 'Content-Security-Policy');

        // 🔥 修复：调整风险等级阈值，使差异更明显
        if (score < 40 || highRiskIssues >= 2 || missingCSP || criticalCSP) {
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
        const criticalCSPCount = issues.filter(issue => issue.severity === 'critical' && issue.header === 'Content-Security-Policy').length;

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
        if (criticalCSPCount > 0) {
            summary.push(`${criticalCSPCount} critical CSP issues`);
        }

        return `Detected ${summary.join(', ')}`;
    }

    generateIssueBreakdown(issues) {
        const breakdown = {
            missing: issues.filter(i => i.type === 'missing').length,
            misconfigured: issues.filter(i => i.type === 'misconfigured').length,
            metaTag: issues.filter(i => i.type === 'meta-tag').length,
            criticalCSP: issues.filter(i => i.severity === 'critical' && i.header === 'Content-Security-Policy').length,
            totalPenalty: issues.reduce((sum, issue) => sum + (issue.penalty || 0), 0)
        };

        const penaltyBreakdown = issues.map(issue => ({
            header: issue.header,
            type: issue.type,
            penalty: issue.penalty || 0,
            riskLevel: issue.riskLevel,
            severity: issue.severity || 'moderate'
        }));

        return { breakdown, penaltyBreakdown };
    }
}