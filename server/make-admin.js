const path = require('path');
const Database = require('better-sqlite3');

const email = process.argv[2]?.trim().toLowerCase();

if (!email) {
    console.error('كتبي الإيميل ديال حسابك مع الأمر.');
    process.exit(1);
}

const db = new Database(path.join(__dirname, 'users.db'));
const student = db.prepare(
    'SELECT id, name, email FROM students WHERE email = ?'
).get(email);

if (!student) {
    console.error('ما لقيناش حساب مسجل بهاد الإيميل.');
    db.close();
    process.exit(1);
}

db.transaction(() => {
    db.prepare(
        'DELETE FROM admins WHERE student_id != ?'
    ).run(student.id);

    db.prepare(
        'INSERT OR IGNORE INTO admins (student_id) VALUES (?)'
    ).run(student.id);
})();

console.log(`تفعّلت صلاحية الإدارة لـ ${student.name} (${student.email})`);
db.close();