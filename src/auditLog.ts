import fs from 'node:fs';

export class AuditLog {
  private path: string | null;

  constructor(path: string | null) {
    this.path = path;
  }

  write(obj: any) {
    if (!this.path) return;
    try {
      fs.appendFileSync(this.path, JSON.stringify(obj) + '\n', 'utf8');
    } catch {
      // ignore
    }
  }
}

