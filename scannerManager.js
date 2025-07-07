class ScannerManager {
    constructor() {
        this.scanners = new Map();
    }

    register(name, scanner) {
        this.scanners.set(name, scanner);
    }

    async scan(scannerName, data) {
        const scanner = this.scanners.get(scannerName);
        if (!scanner) throw new Error(`Scanner ${scannerName} not found`);
        return await scanner.scan(data);
    }
}

module.exports = ScannerManager;