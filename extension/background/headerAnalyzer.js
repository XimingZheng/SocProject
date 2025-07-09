export default class HeaderAnalyzer {
    constructor() {
        this.securityHeaders = {
            'x-content-type-options': {
                name: 'X-Content-Type-Options',
                description: '防止MIME类型嗅探攻击',
                recommendedValue: 'nosniff',
                riskLevel: 'medium',
                explanation: '此头部防止浏览器对响应内容进行MIME类型猜测，避免恶意内容被执行',
                fixSuggestion: '在服务器响应中添加 X-Content-Type-Options: nosniff',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                description: '防止点击劫持(Clickjacking)攻击',
                recommendedValue: ['DENY', 'SAMEORIGIN'],
                riskLevel: 'high',
                explanation: '此头部防止页面被嵌入到iframe中，避免点击劫持攻击',
                fixSuggestion: '设置 X-Frame-Options: DENY 或 X-Frame-Options: SAMEORIGIN',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            },
            'content-security-policy': {
                name: 'Content-Security-Policy',
                description: '防止XSS和代码注入攻击',
                recommendedValue: null,
                riskLevel: 'high',
                explanation: '此头部定义了页面可以加载的资源，有效防止XSS攻击',
                fixSuggestion: '配置适当的CSP策略，例如：default-src \'self\'',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            },
            'strict-transport-security': {
                name: 'Strict-Transport-Security',
                description: '强制HTTPS连接',
                recommendedValue: null,
                riskLevel: 'medium',
                explanation: '此头部强制浏览器使用HTTPS连接，防止中间人攻击',
                fixSuggestion: '设置 Strict-Transport-Security: max-age=31536000; includeSubDomains',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
            },
            'x-xss-protection': {
                name: 'X-XSS-Protection',
                description: '启用浏览器XSS防护',
                recommendedValue: '1; mode=block',
                riskLevel: 'low',
                explanation: '此头部启用浏览器的XSS过滤器（已被CSP取代，但仍有价值）',
                fixSuggestion: '设置 X-XSS-Protection: 1; mode=block',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection']
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                description: '控制Referrer信息泄露',
                recommendedValue: ['strict-origin-when-cross-origin', 'no-referrer'],
                riskLevel: 'low',
                explanation: '此头部控制浏览器发送referrer信息的策略，防止信息泄露',
                fixSuggestion: '设置 Referrer-Policy: strict-origin-when-cross-origin',
                references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            }
        };
    }

    async scan(headers) {
        const issues = [];
        let totalScore = 0;
        let maxScore = 0;

        for (const [headerKey, headerConfig] of Object.entries(this.securityHeaders)) {
            maxScore += this.getRiskScore(headerConfig.riskLevel);
            const headerValue = headers[headerKey];
            const issue = this.analyzeHeader(headerKey, headerValue, headerConfig);

            if (issue) {
                issues.push(issue);
            } else {
                totalScore += this.getRiskScore(headerConfig.riskLevel);
            }
        }

        const scorePercentage = maxScore > 0 ? totalScore / maxScore : 0;
        const overallRiskLevel = this.calculateOverallRisk(scorePercentage, issues);

        console.log('percentage:', scorePercentage, ';riskLevel:', overallRiskLevel);

        return {
            riskLevel: overallRiskLevel,
            score: Math.round(scorePercentage * 100),
            issues: issues,
            summary: this.generateSummary(issues, overallRiskLevel),
            timestamp: Date.now()
        };
    }

    analyzeHeader(headerKey, headerValue, headerConfig) {
        if (!headerValue) {
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
                    issue: headerValue.toLowerCase() !== 'nosniff' ? '值应为 nosniff' : null
                };

            case 'x-frame-options':
                const validFrameOptions = ['DENY', 'SAMEORIGIN'];
                const isValidFrameOption = validFrameOptions.some(option =>
                    headerValue.toUpperCase().includes(option)
                );
                return {
                    isValid: isValidFrameOption,
                    issue: !isValidFrameOption ? '值应为 DENY 或 SAMEORIGIN' : null
                };

            case 'content-security-policy':
                const hasDefaultSrc = headerValue.includes('default-src');
                const hasUnsafeInline = headerValue.includes("'unsafe-inline'");
                const hasUnsafeEval = headerValue.includes("'unsafe-eval'");

                if (!hasDefaultSrc) {
                    return {
                        isValid: false,
                        issue: '缺少 default-src 指令'
                    };
                }

                if (hasUnsafeInline || hasUnsafeEval) {
                    return {
                        isValid: false,
                        issue: '存在不安全的 unsafe-inline 或 unsafe-eval 指令'
                    };
                }

                return { isValid: true };

            case 'strict-transport-security':
                const hasMaxAge = /max-age=(\d+)/.exec(headerValue);
                if (!hasMaxAge) {
                    return {
                        isValid: false,
                        issue: '缺少 max-age 指令'
                    };
                }

                const maxAge = parseInt(hasMaxAge[1]);
                if (maxAge < 31536000) {
                    return {
                        isValid: false,
                        issue: 'max-age 值太小，建议至少设置为 31536000 (1年)'
                    };
                }

                return { isValid: true };

            case 'x-xss-protection':
                const validXSSProtection = ['1', '1; mode=block'];
                return {
                    isValid: validXSSProtection.includes(headerValue),
                    issue: !validXSSProtection.includes(headerValue) ? '推荐设置为 1; mode=block' : null
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
                    issue: !validReferrerPolicies.includes(headerValue) ? '无效的 Referrer-Policy 值' : null
                };

            default:
                return { isValid: true };
        }
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

        if (highRiskIssues >= 2 || scorePercentage < 0.4) {
            return 'high';
        } else if (highRiskIssues >= 1 || mediumRiskIssues >= 2 || scorePercentage < 0.7) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    generateSummary(issues, overallRiskLevel) {
        if (issues.length === 0) {
            return '✅ 当前页面的安全响应头配置良好';
        }

        const highRiskCount = issues.filter(issue => issue.riskLevel === 'high').length;
        const mediumRiskCount = issues.filter(issue => issue.riskLevel === 'medium').length;
        const lowRiskCount = issues.filter(issue => issue.riskLevel === 'low').length;

        let summary = '';
        if (highRiskCount > 0) {
            summary += `发现 ${highRiskCount} 个高风险问题`;
        }
        if (mediumRiskCount > 0) {
            summary += `${summary ? '，' : '发现 '}${mediumRiskCount} 个中风险问题`;
        }
        if (lowRiskCount > 0) {
            summary += `${summary ? '，' : '发现 '}${lowRiskCount} 个低风险问题`;
        }

        return summary;
    }
}
