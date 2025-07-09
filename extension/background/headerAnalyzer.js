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
                const hasDefaultSrc = headerValue.includes('default-src');
                const hasUnsafeInline = headerValue.includes("'unsafe-inline'");
                const hasUnsafeEval = headerValue.includes("'unsafe-eval'");

                if (!hasDefaultSrc) {
                    return {
                        isValid: false,
                        issue: 'Missing default-src directive'
                    };
                }

                if (hasUnsafeInline || hasUnsafeEval) {
                    return {
                        isValid: false,
                        issue: 'Unsafe directive present: unsafe-inline or unsafe-eval'
                    };
                }

                return { isValid: true };

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
            return '✅ Security headers are properly configured for this page';
        }

        const highRiskCount = issues.filter(issue => issue.riskLevel === 'high').length;
        const mediumRiskCount = issues.filter(issue => issue.riskLevel === 'medium').length;
        const lowRiskCount = issues.filter(issue => issue.riskLevel === 'low').length;

        let summary = '';
        if (highRiskCount > 0) {
            summary += `Detected ${highRiskCount}  high-risk issues`;
        }
        if (mediumRiskCount > 0) {
            summary += `${summary ? ', ' : 'Detected '}${mediumRiskCount}  medium-risk issues`;
        }
        if (lowRiskCount > 0) {
            summary += `${summary ? ', ' : 'Detected '}${lowRiskCount}  low-risk issues`;
        }

        return summary;
    }
}
