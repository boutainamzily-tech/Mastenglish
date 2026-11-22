const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const { DateTime } = require('luxon');
module.exports = function setupAuth(app) {
    const secret = process.env.AUTH_SECRET;
    if (!secret || secret.length < 32) {
        throw new Error('AUTH_SECRET is missing');
    }

    const db = new Database(path.join(__dirname, 'users.db'));
    db.pragma('journal_mode = WAL');
    db.exec(`
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    `);
db.exec(`
    CREATE TABLE IF NOT EXISTS lesson_access (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        access_type TEXT NOT NULL CHECK (access_type IN ('trial', 'monthly')),
        starts_at TEXT NOT NULL,
        ends_at TEXT NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(id)
    )
`);
db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
        student_id INTEGER PRIMARY KEY,
        FOREIGN KEY (student_id) REFERENCES students(id)
    )
`);
db.exec(`
    CREATE TABLE IF NOT EXISTS booking_slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        starts_at TEXT NOT NULL,
        ends_at TEXT NOT NULL,
        is_open INTEGER NOT NULL DEFAULT 1
            CHECK (is_open IN (0, 1)),
        CHECK (ends_at > starts_at),
        UNIQUE (starts_at, ends_at)
    );

    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        slot_id INTEGER NOT NULL,
        program TEXT NOT NULL
            CHECK (program IN ('kids', 'adults', 'one-on-one')),
        learner_name TEXT NOT NULL,
        learner_age INTEGER
            CHECK (learner_age BETWEEN 4 AND 120),
        notes TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN (
                'pending',
                'confirmed',
                'cancelled',
                'rejected',
                'completed',
                'no_show'
            )),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(id),
        FOREIGN KEY (slot_id) REFERENCES booking_slots(id)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS booking_slot_reserved
    ON bookings (slot_id)
    WHERE status IN (
        'pending', 'confirmed', 'completed', 'no_show'
    );

    CREATE INDEX IF NOT EXISTS bookings_student
    ON bookings (student_id);
`);
db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        student_id INTEGER PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(id)
    );
`);
const studentColumns = db.prepare(
    'PRAGMA table_info(students)'
).all();

if (!studentColumns.some(column => column.name === 'session_version')) {
    db.exec(`
        ALTER TABLE students
        ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0
    `);
}
db.exec(`
    CREATE TABLE IF NOT EXISTS class_groups (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        program TEXT NOT NULL
            CHECK (program IN ('kids', 'adults', 'one-on-one'))
    );

    CREATE TABLE IF NOT EXISTS class_enrollments (
        group_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        PRIMARY KEY (group_id, student_id),
        FOREIGN KEY (group_id) REFERENCES class_groups(id),
        FOREIGN KEY (student_id) REFERENCES students(id)
    );

    CREATE TABLE IF NOT EXISTS class_sessions (
        id INTEGER PRIMARY KEY,
        group_id INTEGER NOT NULL,
        starts_at TEXT NOT NULL,
        UNIQUE (group_id, starts_at),
        FOREIGN KEY (group_id) REFERENCES class_groups(id)
    );
`);
   app.set('trust proxy', 'loopback');
    app.use(cookieParser());

    const cookieOptions = {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/',
        maxAge: 12 * 60 * 60 * 1000
    };

    function currentStudent(req) {
    const token = req.cookies?.student_session;
    if (!token) return null;

    try {
        const data = jwt.verify(token, secret, {
            algorithms: ['HS256']
        });

        const student = db.prepare(`
            SELECT id, name, email, session_version
            FROM students
            WHERE id = ?
        `).get(data.studentId);

        if (!student) return null;

        const tokenVersion = data.sessionVersion ?? 0;

        if (tokenVersion !== student.session_version) {
            return null;
        }

        return {
            id: student.id,
            name: student.name,
            email: student.email
        };
    } catch {
        return null;
    }
}

    function requireStudent(req, res, next) {
        const student = currentStudent(req);
        if (!student) {
            return res.status(401).json({
                error: 'خاصك تسجل الدخول أولاً'
            });
        }
        req.student = student;
        next();
    }
function requireAdmin(req, res, next) {
    const student = currentStudent(req);

    if (!student) {
        return res.status(401).json({ error: 'خاصك تسجل الدخول أولاً' });
    }

    const admin = db.prepare(
        'SELECT student_id FROM admins WHERE student_id = ?'
    ).get(student.id);

    if (!admin) {
        return res.status(403).json({ error: 'هاد الصفحة خاصة بالإدارة' });
    }

    req.student = student;
    next();
}
    function signIn(res, student) {
    const account = db.prepare(`
        SELECT session_version
        FROM students
        WHERE id = ?
    `).get(student.id);

    if (!account) {
        throw new Error('Student account not found');
    }

    const token = jwt.sign(
        {
            studentId: student.id,
            sessionVersion: account.session_version
        },
        secret,
        {
            algorithm: 'HS256',
            expiresIn: '12h'
        }
    );

    res.cookie('student_session', token, cookieOptions);
}
    
const resetMailer =
    process.env.SMTP_USER && process.env.SMTP_PASS
        ? nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            },
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 15000
        })
        : null;
        const { rateLimit: resetRateLimit } = require('express-rate-limit');

const forgotPasswordLimiter = resetRateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
        error: 'محاولات كثيرة. تسنّى 15 دقيقة وعاود المحاولة.'
    }
});

const resetPasswordLimiter = resetRateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
        error: 'محاولات كثيرة. تسنّى 15 دقيقة وعاود المحاولة.'
    }
});
app.post('/auth/forgot-password', forgotPasswordLimiter, (req, res) => {
    res.set('Cache-Control', 'no-store');

    if (!resetMailer) {
        return res.status(503).json({
            error: 'خدمة استرجاع كلمة المرور مازال ما تفعّلاتش. عاود المحاولة من بعد.'
        });
    }

    let resetOrigin;

    try {
        const configuredOrigin = process.env.PUBLIC_ORIGIN ||
            (process.env.NODE_ENV !== 'production'
                ? 'http://127.0.0.1:3000' : '');

        const url = new URL(configuredOrigin);

        const localDevelopment =
            process.env.NODE_ENV !== 'production' &&
            url.protocol === 'http:' &&
            ['127.0.0.1', 'localhost'].includes(url.hostname);

        if ((url.protocol !== 'https:' && !localDevelopment) ||
            url.username || url.password ||
            url.pathname !== '/' || url.search || url.hash) {
            throw new Error('Invalid reset origin');
        }

        resetOrigin = url.origin;
    } catch {
        return res.status(503).json({
            error: 'خدمة الاسترجاع غير متاحة حالياً. عاود المحاولة من بعد.'
        });
    }

    const email = typeof req.body?.email === 'string'
        ? req.body.email.trim().toLowerCase()
        : '';

    res.status(202).json({
        message: 'إلا كان هاد البريد مسجّل، غادي توصلك رسالة فيها رابط الاسترجاع. شوف حتى البريد غير المرغوب فيه.'
    });

    setImmediate(async () => {
        try {
            if (!email || email.length > 254) return;

            const student = db.prepare(
                'SELECT id, email FROM students WHERE email = ?'
            ).get(email);

            if (!student) return;

            const now = Date.now();
            const token = crypto.randomBytes(32).toString('hex');
            const tokenHash = crypto.createHash('sha256')
                .update(token).digest('hex');

            const result = db.prepare(`
                INSERT INTO password_reset_tokens
                    (student_id, token_hash, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(student_id) DO UPDATE SET
                    token_hash = excluded.token_hash,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                WHERE password_reset_tokens.created_at <= ?
            `).run(
                student.id,
                tokenHash,
                now,
                now + 15 * 60 * 1000,
                now - 5 * 60 * 1000
            );

            if (result.changes === 0) return;

            const resetLink =
                `${resetOrigin}/reset-password.html#token=${token}`;

            await resetMailer.sendMail({
                from: process.env.SMTP_USER,
                to: student.email,
                subject: 'Mastenglish — استرجاع كلمة المرور',
                text: [
                    'توصلنا بطلب تغيير كلمة المرور ديال حسابك فـ Mastenglish.',
                    'باش تختار كلمة مرور جديدة، افتح هاد الرابط:',
                    resetLink,
                    'الرابط صالح لمدة 15 دقيقة وكيستعمل مرة واحدة.',
                    'إلا ما طلبتيش هاد التغيير، تجاهل الرسالة. كلمة المرور ديالك ما تبدلاتش.'
                ].join('\n\n')
            });
        } catch (error) {
            console.error(
                'Password reset email failed:',
                error.code || 'SEND_FAILED'
            );
        }
    });
});
app.post('/auth/reset-password', resetPasswordLimiter, async (req, res) => {
    res.set('Cache-Control', 'no-store');

    const token = req.body?.token;
    const password = req.body?.password;
    const confirmation = req.body?.password_confirmation;
    const invalidLink =
        'الرابط غير صالح أو انتهت صلاحيته. طلب رابطاً جديداً.';

    if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
        return res.status(400).json({ error: invalidLink });
    }

    if (typeof password !== 'string' || password.length < 8 ||
        Buffer.byteLength(password, 'utf8') > 72 ||
        password !== confirmation) {
        return res.status(400).json({
            error: 'كلمة السر خاصها 8 حروف على الأقل، ما تكونش طويلة بزاف، والتأكيد يكون مطابقاً.'
        });
    }

    try {
        const tokenHash = crypto.createHash('sha256')
            .update(token).digest('hex');

        const findToken = db.prepare(`
            SELECT student_id FROM password_reset_tokens
            WHERE token_hash = ? AND expires_at > ?
        `);

        if (!findToken.get(tokenHash, Date.now())) {
            return res.status(400).json({ error: invalidLink });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const changePassword = db.transaction(() => {
            const reset = findToken.get(tokenHash, Date.now());
            if (!reset) return null;

            const student = db.prepare(
                'SELECT id, email FROM students WHERE id = ?'
            ).get(reset.student_id);

            if (!student) return null;

            db.prepare(`
                UPDATE students
                SET password_hash = ?,
                    session_version = session_version + 1
                WHERE id = ?
            `).run(passwordHash, student.id);

            db.prepare(
                'DELETE FROM password_reset_tokens WHERE student_id = ?'
            ).run(student.id);

            return student;
        });

        const student = changePassword.immediate();

        if (!student) {
            return res.status(400).json({ error: invalidLink });
        }

        res.clearCookie('student_session', {
            path: '/',
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production'
        });

        res.json({
            message: 'تبدّلات كلمة المرور بنجاح. سجّل الدخول بالكلمة الجديدة.'
        });

        if (resetMailer) {
            resetMailer.sendMail({
                from: process.env.SMTP_USER,
                to: student.email,
                subject: 'Mastenglish — تم تغيير كلمة المرور',
                text: 'تغيّرات كلمة المرور ديال حسابك فـ Mastenglish. إلا ما كنتيش نتي اللي بدّلتيها، استرجع الحساب من الموقع وتأكد من أمان بريدك الإلكتروني.'
            }).catch(error => {
                console.error(
                    'Password change notice failed:',
                    error.code || 'SEND_FAILED'
                );
            });
        }
    } catch (error) {
        console.error(
            'Password reset failed:',
            error.code || 'RESET_FAILED'
        );

        if (!res.headersSent) {
            res.status(500).json({
                error: 'تعذر تغيير كلمة المرور. عاود المحاولة.'
            });
        }
    }
});
    app.post('/auth/register', async (req, res) => {
        const name = String(req.body?.name || '').trim();
        const email = String(req.body?.email || '').trim().toLowerCase();
        const password = String(req.body?.password || '');

        if (name.length < 2 || name.length > 80 ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    password.length < 8 ||
    Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({
        error: 'تأكدي من الاسم والبريد. كلمة السر خاصها 8 حروف على الأقل؛ إلا كانت طويلة بزاف، قصّريها.'
    });
}

        try {
            const hash = await bcrypt.hash(password, 12);
            const result = db.prepare(
                'INSERT INTO students (name, email, password_hash) VALUES (?, ?, ?)'
            ).run(name, email, hash);

            const student = { id: result.lastInsertRowid, name, email };
            signIn(res, student);
            res.status(201).json({ student });
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                return res.status(409).json({
                    error: 'هاد البريد مسجل من قبل'
                });
            }
            console.error('Registration error:', error);
            res.status(500).json({ error: 'وقع مشكل أثناء التسجيل' });
        }
    });

    app.post('/auth/login', async (req, res) => {
        const email = String(req.body?.email || '').trim().toLowerCase();
        const password = String(req.body?.password || '');
if (email.length > 254 || !email ||
    !password || Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(401).json({
        error: 'البريد الإلكتروني أو كلمة السر غير صحيحة'
    });
}
        const account = db.prepare(
            'SELECT * FROM students WHERE email = ?'
        ).get(email);

        if (!account || !(await bcrypt.compare(password, account.password_hash))) {
            return res.status(401).json({
                error: 'البريد الإلكتروني أو كلمة السر غير صحيحة'
            });
        }

        const student = {
            id: account.id,
            name: account.name,
            email: account.email
        };
        signIn(res, student);
        res.json({ student });
    });
app.get('/auth/me', requireStudent, (req, res) => {
    const isAdmin = Boolean(
        db.prepare(
            'SELECT student_id FROM admins WHERE student_id = ?'
        ).get(req.student.id)
    );

    res.json({
        student: req.student,
        isAdmin
    });
});
    app.post('/auth/logout', (req, res) => {
        res.clearCookie('student_session', {
            path: '/',
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production'
        });
        res.json({ ok: true });
    });

   function requireStudentPage(req, res, next) {
    const student = currentStudent(req);
    if (!student) return res.redirect('/login.html');
    req.student = student;
    next();
}
app.post('/admin/booking-slots', requireAdmin, (req, res) => {
    const { date, start_time, end_time } = req.body || {};

    if (typeof date !== 'string' ||
        typeof start_time !== 'string' ||
        typeof end_time !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(start_time) ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(end_time)) {
        return res.status(400).json({
            error: 'اختاري النهار وساعة البداية والنهاية'
        });
    }

    const startText = `${date}T${start_time}`;
    const endText = `${date}T${end_time}`;
    const options = { zone: 'Africa/Casablanca' };

    const start = DateTime.fromISO(startText, options);
    const end = DateTime.fromISO(endText, options);

    if (!start.isValid || !end.isValid ||
        start.toFormat("yyyy-MM-dd'T'HH:mm") !== startText ||
        end.toFormat("yyyy-MM-dd'T'HH:mm") !== endText ||
        start.getPossibleOffsets().length !== 1 ||
        end.getPossibleOffsets().length !== 1) {
        return res.status(400).json({
            error: 'هاد التوقيت غير صالح أو ملتبس بسبب تغيير الساعة. اختاري وقتاً آخر.'
        });
    }

    if (start.toMillis() <= Date.now() ||
        end.toMillis() <= start.toMillis()) {
        return res.status(400).json({
            error: 'اختاري موعداً مستقبلياً، والنهاية تكون من بعد البداية فنفس النهار'
        });
    }

    const startsAt = start.toUTC().toISO();
    const endsAt = end.toUTC().toISO();

    try {
        const createSlot = db.transaction(() => {
            const overlap = db.prepare(`
                SELECT id
                FROM booking_slots
                WHERE starts_at < ? AND ends_at > ?
                LIMIT 1
            `).get(endsAt, startsAt);

            if (overlap) return null;

            return db.prepare(`
                INSERT INTO booking_slots (starts_at, ends_at)
                VALUES (?, ?)
            `).run(startsAt, endsAt).lastInsertRowid;
        });

        const id = createSlot.immediate();

        if (id === null) {
            return res.status(409).json({
                error: 'هاد الوقت كيتداخل مع موعد موجود'
            });
        }

        res.status(201).json({
            slot: { id, starts_at: startsAt, ends_at: endsAt }
        });
    } catch (error) {
        console.error('Create booking slot error:', error);
        res.status(500).json({
            error: 'تعذر حفظ الموعد'
        });
    }
});
app.get('/bookings', requireStudent, (req, res) => {
    res.set('Cache-Control', 'no-store');

    const bookings = db.prepare(`
        SELECT
            b.id,
            b.program,
            b.learner_name,
            b.learner_age,
            b.status,
            s.starts_at,
            s.ends_at
        FROM bookings b
        JOIN booking_slots s ON s.id = b.slot_id
        WHERE b.student_id = ?
        ORDER BY s.starts_at DESC, b.id DESC
    `).all(req.student.id);

    res.json({ bookings });
});
app.post('/bookings/:id/cancel', requireStudent, (req, res) => {
    const bookingId = Number(req.params.id);

    if (!Number.isSafeInteger(bookingId) || bookingId < 1) {
        return res.status(400).json({
            error: 'رقم الحجز غير صحيح'
        });
    }

    try {
        const result = db.prepare(`
            UPDATE bookings
            SET status = 'cancelled', updated_at = ?
            WHERE id = ?
              AND student_id = ?
              AND status = 'pending'
        `).run(
            new Date().toISOString(),
            bookingId,
            req.student.id
        );

        if (result.changes === 0) {
            return res.status(409).json({
                error: 'الطلب ما بقاش قابل للإلغاء أو ما لقيناهش فحسابك. حدّث الصفحة.'
            });
        }

        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, status: 'cancelled' });
    } catch (error) {
        console.error('Booking cancellation error:', error);
        res.status(500).json({
            error: 'تعذر إلغاء الطلب. عاود المحاولة.'
        });
    }
});
async function notifyNewBooking(bookingId) {
    try {
        if (!resetMailer) return;

        const booking = db.prepare(`
            SELECT
                b.id,
                b.program,
                b.learner_name,
                b.learner_age,
                s.name AS account_name,
                s.email,
                t.starts_at,
                t.ends_at
            FROM bookings b
            JOIN students s ON s.id = b.student_id
            JOIN booking_slots t ON t.id = b.slot_id
            WHERE b.id = ?
        `).get(bookingId);

        if (!booking) return;

        const programNames = {
            kids: 'الصغار والمراهقون',
            adults: 'الكبار',
            'one-on-one': 'حصص فردية خاصة'
        };

        const formatter = new Intl.DateTimeFormat('ar-MA', {
            timeZone: 'Africa/Casablanca',
            dateStyle: 'full',
            timeStyle: 'short'
        });

        const adminUrl = new URL(
            '/admin.html',
            process.env.PUBLIC_ORIGIN || 'http://127.0.0.1:3000'
        ).href;

        await resetMailer.sendMail({
            from: process.env.SMTP_USER,
            to: process.env.SMTP_USER,
            replyTo: booking.email,
            subject: `Mastenglish — طلب حجز جديد رقم ${booking.id}`,
            text: [
                'توصلتي بطلب حجز جديد، مازال فانتظار التأكيد.',
                `رقم الطلب: ${booking.id}`,
                `المستفيد: ${booking.learner_name}`,
                `العمر: ${booking.learner_age}`,
                `البرنامج: ${programNames[booking.program] || booking.program}`,
                `صاحب الحساب: ${booking.account_name}`,
                `البريد الإلكتروني: ${booking.email}`,
                `البداية: ${formatter.format(new Date(booking.starts_at))}`,
                `النهاية: ${formatter.format(new Date(booking.ends_at))}`,
                'جميع الأوقات بتوقيت المغرب.',
                'راجعي الطلب من لوحة الإدارة لتأكيده أو رفضه:',
                adminUrl
            ].join('\n\n')
        });
    } catch (error) {
        console.error(
            'Booking notification failed:',
            error.code || 'SEND_FAILED'
        );
    }
}
app.post('/bookings', requireStudent, (req, res) => {
    const body = req.body || {};
    const slotId = Number(body.slot_id);
    const program = body.program;
    const learnerName = typeof body.learner_name === 'string'
        ? body.learner_name.trim()
        : '';
    const learnerAge = Number(body.learner_age);

    if (!Number.isSafeInteger(slotId) || slotId < 1 ||
        !['kids', 'adults', 'one-on-one'].includes(program) ||
        learnerName.length < 2 || learnerName.length > 80 ||
        !Number.isInteger(learnerAge) ||
        learnerAge < 4 || learnerAge > 120) {
        return res.status(400).json({
            error: 'تأكدي من البرنامج والاسم والعمر والموعد'
        });
    }

    try {
        const saveBooking = db.transaction(() => {
            const previousTrial = db.prepare(`
                SELECT id FROM lesson_access
                WHERE student_id = ? AND access_type = 'trial'
                LIMIT 1
            `).get(req.student.id);

            if (previousTrial) {
                return { error: 'سبق تفعيل التجربة لهاد الحساب' };
            }

            const now = new Date().toISOString();

// إلغاء الطلبات غير المؤكدة اللي فات وقت بدايتها.
db.prepare(`
    UPDATE bookings
    SET status = 'cancelled', updated_at = ?
    WHERE student_id = ?
      AND status = 'pending'
      AND slot_id IN (
          SELECT id FROM booking_slots
          WHERE starts_at <= ?
      )
`).run(now, req.student.id, now);

const existing = db.prepare(`
    SELECT id FROM bookings
    WHERE student_id = ?
      AND status IN (
          'pending', 'confirmed', 'completed', 'no_show'
      )
    LIMIT 1
`).get(req.student.id);

if (existing) {
    return {
        error: 'عندك طلب تجربة مسجّل من قبل. راجع صفحة «حجوزاتي».'
    };
}

            const slot = db.prepare(`
                SELECT id FROM booking_slots
                WHERE id = ? AND is_open = 1 AND starts_at > ?
                  AND NOT EXISTS (
                      SELECT 1 FROM bookings b
                      WHERE b.slot_id = booking_slots.id
                        AND b.status IN (
                            'pending', 'confirmed', 'completed', 'no_show'
                        )
                  )
            `).get(slotId, now);

            if (!slot) {
                return {
                    error: 'هاد الموعد ما بقاش متاح. اختاري موعداً آخر.'
                };
            }

            const result = db.prepare(`
                INSERT INTO bookings (
                    student_id, slot_id, program,
                    learner_name, learner_age,
                    status, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
            `).run(
                req.student.id, slotId, program,
                learnerName, learnerAge, now, now
            );

            return { id: result.lastInsertRowid };
        });

        const result = saveBooking.immediate();

        if (result.error) {
            return res.status(409).json({ error: result.error });
        }

        res.set('Cache-Control', 'no-store');
        res.status(201).json({
            booking: {
                id: result.id,
                status: 'pending'
            }
        });
        void notifyNewBooking(result.id);
    } catch (error) {
        console.error('Booking error:', error);
        res.status(500).json({
            error: 'تعذر حفظ طلب الحجز'
        });
    }
});
app.get('/booking-slots', requireStudent, (req, res) => {
    res.set('Cache-Control', 'no-store');

    const slots = db.prepare(`
        SELECT s.id, s.starts_at, s.ends_at
        FROM booking_slots s
        WHERE s.is_open = 1
          AND s.starts_at > ?
          AND NOT EXISTS (
              SELECT 1
              FROM bookings b
              WHERE b.slot_id = s.id
                AND b.status IN (
                    'pending', 'confirmed', 'completed', 'no_show'
                )
          )
        ORDER BY s.starts_at ASC
    `).all(new Date().toISOString());

    res.json({ slots });
});
app.post('/admin/booking-slots/:id/state', requireAdmin, (req, res) => {
    const slotId = Number(req.params.id);
    const isOpen = req.body?.is_open;

    if (!Number.isSafeInteger(slotId) || slotId < 1 ||
        typeof isOpen !== 'boolean') {
        return res.status(400).json({
            error: 'الموعد أو الحالة غير صحيحة'
        });
    }

    try {
        const result = db.prepare(`
            UPDATE booking_slots
            SET is_open = ?
            WHERE id = ?
              AND starts_at > ?
              AND NOT EXISTS (
                  SELECT 1 FROM bookings b
                  WHERE b.slot_id = booking_slots.id
                    AND b.status IN (
                        'pending', 'confirmed', 'completed', 'no_show'
                    )
              )
        `).run(
            isOpen ? 1 : 0,
            slotId,
            new Date().toISOString()
        );

        if (result.changes === 0) {
            return res.status(409).json({
                error: 'ما قدرناش نبدلو هاد الموعد: يمكن محجوز، فات وقتو، أو ما بقاش موجود. حدّثي اللائحة.'
            });
        }

        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, is_open: isOpen });
    } catch (error) {
        console.error('Slot state error:', error);
        res.status(500).json({
            error: 'تعذر تغيير حالة الموعد'
        });
    }
});
app.get('/admin/booking-slots', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');

    const slots = db.prepare(`
        SELECT
            s.id,
            s.starts_at,
            s.ends_at,
            s.is_open,
            EXISTS (
                SELECT 1
                FROM bookings b
                WHERE b.slot_id = s.id
                  AND b.status IN (
                      'pending', 'confirmed', 'completed', 'no_show'
                  )
            ) AS reserved
        FROM booking_slots s
        ORDER BY s.starts_at ASC
    `).all();

    res.json({ slots });
});
async function notifyBookingDecision(bookingId, decision) {
    try {
        if (!resetMailer) return;

        if (!['confirmed', 'rejected'].includes(decision)) {
            return;
        }

        const booking = db.prepare(`
            SELECT
                b.id,
                b.program,
                b.learner_name,
                b.status,
                s.email,
                t.starts_at,
                t.ends_at
            FROM bookings b
            JOIN students s ON s.id = b.student_id
            JOIN booking_slots t ON t.id = b.slot_id
            WHERE b.id = ?
        `).get(bookingId);

        if (!booking || booking.status !== decision) return;

        const programNames = {
            kids: 'الصغار والمراهقون',
            adults: 'الكبار',
            'one-on-one': 'حصص فردية خاصة'
        };

        const formatter = new Intl.DateTimeFormat('ar-MA', {
            timeZone: 'Africa/Casablanca',
            dateStyle: 'full',
            timeStyle: 'short'
        });

        const bookingsUrl = new URL(
            '/my-bookings.html',
            process.env.PUBLIC_ORIGIN || 'http://127.0.0.1:3000'
        ).href;

        const confirmed = decision === 'confirmed';

        const introduction = confirmed
            ? 'تأكّد الحجز ديال حصتك التجريبية. مرحبا بيك!'
            : 'تعذّر تأكيد هاد الطلب. تقدر تختار موعداً متاحاً آخر من الموقع.';

        const instructions = confirmed
            ? 'فوقت الموعد، سجّل الدخول بنفس الحساب وافتح «حجوزاتي». غادي يبان ليك زر الدخول للحصة.'
            : 'شوف حالة الطلب من «حجوزاتي»، ومن بعدها تقدر ترجع لصفحة الحجز.';

        await resetMailer.sendMail({
            from: process.env.SMTP_USER,
            to: booking.email,
            replyTo: process.env.SMTP_USER,
            subject: confirmed
                ? `Mastenglish — تأكيد الحجز رقم ${booking.id}`
                : `Mastenglish — بخصوص طلب الحجز رقم ${booking.id}`,
            text: [
                introduction,
                `رقم الطلب: ${booking.id}`,
                `المستفيد: ${booking.learner_name}`,
                `البرنامج: ${programNames[booking.program] || booking.program}`,
                `بداية الموعد: ${formatter.format(new Date(booking.starts_at))}`,
                `نهاية الموعد: ${formatter.format(new Date(booking.ends_at))}`,
                'جميع الأوقات بتوقيت المغرب.',
                instructions,
                bookingsUrl
            ].join('\n\n')
        });
    } catch (error) {
        console.error(
            'Booking decision email failed:',
            error.code || 'SEND_FAILED'
        );
    }
}
app.post('/admin/bookings/:id/decision', requireAdmin, (req, res) => {
    const bookingId = Number(req.params.id);
    const decision = req.body?.decision;

    if (!Number.isSafeInteger(bookingId) || bookingId < 1 ||
        !['confirmed', 'rejected'].includes(decision)) {
        return res.status(400).json({
            error: 'الطلب أو القرار غير صحيح'
        });
    }

    try {
        const decide = db.transaction(() => {
            const booking = db.prepare(`
                SELECT b.*, s.starts_at, s.ends_at, s.is_open
                FROM bookings b
                JOIN booking_slots s ON s.id = b.slot_id
                WHERE b.id = ?
            `).get(bookingId);

            if (!booking) {
                return { code: 404, error: 'طلب الحجز ما لقيناهش' };
            }

            if (booking.status !== 'pending') {
                return {
                    code: 409,
                    error: 'هاد الطلب تعالج من قبل. حدّثي الصفحة.'
                };
            }

            const now = new Date().toISOString();

            if (decision === 'confirmed') {
                if (!booking.is_open || booking.starts_at <= now) {
                    return {
                        code: 409,
                        error: 'الموعد مغلق أو وقت البداية ديالو داز'
                    };
                }

                const trial = db.prepare(`
                    SELECT id FROM lesson_access
                    WHERE student_id = ? AND access_type = 'trial'
                    LIMIT 1
                `).get(booking.student_id);

                if (trial) {
                    return {
                        code: 409,
                        error: 'سبق تفعيل تجربة لهاد الحساب'
                    };
                }

                db.prepare(`
                    INSERT INTO lesson_access (
                        student_id, access_type, starts_at, ends_at
                    )
                    VALUES (?, 'trial', ?, ?)
                `).run(
                    booking.student_id,
                    booking.starts_at,
                    booking.ends_at
                );
            }

            db.prepare(`
                UPDATE bookings
                SET status = ?, updated_at = ?
                WHERE id = ?
            `).run(decision, now, bookingId);

            return { ok: true };
        });

        const result = decide.immediate();

        if (result.error) {
            return res.status(result.code).json({
                error: result.error
            });
        }

        res.json({ ok: true, status: decision });
        void notifyBookingDecision(bookingId, decision);
    } catch (error) {
        console.error('Booking decision error:', error);
        res.status(500).json({
            error: 'تعذر حفظ القرار'
        });
    }
});
app.post('/admin/class-groups/:id/enroll', requireAdmin, (req, res) => {
    const groupId = Number(req.params.id);
    const studentId = req.body?.student_id;

    if (!Number.isSafeInteger(groupId) || groupId < 1 ||
        !Number.isSafeInteger(studentId) || studentId < 1) {
        return res.status(400).json({
            error: 'اختاري المجموعة والتلميذ.'
        });
    }

    try {
        const enroll = db.transaction(() => {
            const group = db.prepare(
                'SELECT program FROM class_groups WHERE id = ?'
            ).get(groupId);

            const student = db.prepare(
                'SELECT id FROM students WHERE id = ?'
            ).get(studentId);

            if (!group || !student) {
                return { code: 404, error: 'المجموعة أو التلميذ ما لقيناهش.' };
            }

            const existing = db.prepare(`
                SELECT 1 FROM class_enrollments
                WHERE group_id = ? AND student_id = ?
            `).get(groupId, studentId);

            if (existing) {
                return { code: 409, error: 'هاد التلميذ مسجّل فهاد المجموعة من قبل.' };
            }

            const { total } = db.prepare(`
                SELECT COUNT(*) AS total FROM class_enrollments
                WHERE group_id = ?
            `).get(groupId);

            const capacity = group.program === 'one-on-one' ? 1 : 4;

            if (total >= capacity) {
                return { code: 409, error: 'هاد المجموعة عامرة.' };
            }

            db.prepare(`
                INSERT INTO class_enrollments (group_id, student_id)
                VALUES (?, ?)
            `).run(groupId, studentId);

            return { ok: true };
        });

        const result = enroll.immediate();

        if (result.error) {
            return res.status(result.code).json({ error: result.error });
        }

        res.status(201).json({ ok: true });
    } catch (error) {
        console.error('Class enrollment failed:', error.code);
        res.status(500).json({ error: 'تعذر إضافة التلميذ.' });
    }
});
app.post('/admin/class-groups/:id/sessions', requireAdmin, (req, res) => {
    const groupId = Number(req.params.id);
    const { date, start_time } = req.body || {};

    if (!Number.isSafeInteger(groupId) || groupId < 1 ||
        typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
        typeof start_time !== 'string' ||
        !/^([01]\d|2[0-3]):[0-5]\d$/.test(start_time)) {
        return res.status(400).json({
            error: 'اختاري المجموعة والنهار وساعة البداية.'
        });
    }

    const start = DateTime.fromISO(`${date}T${start_time}`, {
        zone: 'Africa/Casablanca'
    });

    if (!start.isValid ||
        start.toFormat('yyyy-MM-dd HH:mm') !== `${date} ${start_time}` ||
        start.getPossibleOffsets().length !== 1 ||
        start.toMillis() <= Date.now()) {
        return res.status(400).json({
            error: 'اختاري تاريخاً ووقتاً صالحين فالمستقبل.'
        });
    }

    const startsAt = start.toUTC().toISO();
    const endsAt = start.plus({ minutes: 40 }).toUTC().toISO();
    const earliestOverlap = start.minus({ minutes: 40 }).toUTC().toISO();
    const monthStart = start.startOf('month').toUTC().toISO();
    const nextMonth = start.startOf('month').plus({ months: 1 }).toUTC().toISO();

    try {
        const saveSession = db.transaction(() => {
            const group = db.prepare(
                'SELECT id FROM class_groups WHERE id = ?'
            ).get(groupId);

            if (!group) {
                return { code: 404, error: 'المجموعة ما لقيناهاش.' };
            }

            const regularOverlap = db.prepare(`
                SELECT id FROM class_sessions
                WHERE starts_at > ? AND starts_at < ?
                LIMIT 1
            `).get(earliestOverlap, endsAt);

            const trialOverlap = db.prepare(`
                SELECT id FROM booking_slots
                WHERE is_open = 1 AND starts_at < ? AND ends_at > ?
                LIMIT 1
            `).get(endsAt, startsAt);

            if (regularOverlap || trialOverlap) {
                return {
                    code: 409,
                    error: 'هاد التوقيت كيتداخل مع حصة أو موعد تجربة موجود.'
                };
            }

            const { total } = db.prepare(`
                SELECT COUNT(*) AS total FROM class_sessions
                WHERE group_id = ? AND starts_at >= ? AND starts_at < ?
            `).get(groupId, monthStart, nextMonth);

            if (total >= 12) {
                return {
                    code: 409,
                error: 'هاد المجموعة عندها 12 حصة مبرمجة فهاد الشهر.'
                };
            }

            const result = db.prepare(`
                INSERT INTO class_sessions (group_id, starts_at)
                VALUES (?, ?)
            `).run(groupId, startsAt);

            return {
                session: {
                    id: result.lastInsertRowid,
                    group_id: groupId,
                    starts_at: startsAt,
                    ends_at: endsAt
                }
            };
        });

        const result = saveSession.immediate();

        if (result.error) {
            return res.status(result.code).json({ error: result.error });
        }

        res.status(201).json(result);
    } catch (error) {
        console.error('Class session creation failed:', error.code);
        res.status(500).json({ error: 'تعذر حفظ موعد الحصة.' });
    }
});
app.get('/my-payment-info', requireStudent, (req, res) => {
    res.set('Cache-Control', 'no-store');

    try {
        const groups = db.prepare(`
            SELECT g.id, g.name, g.program
            FROM class_enrollments e
            JOIN class_groups g ON g.id = e.group_id
            WHERE e.student_id = ?
            ORDER BY g.name, g.id
        `).all(req.student.id);

        if (!groups.length) {
            return res.status(403).json({
                error: 'معلومات الأداء غتبان ملي الأستاذة تضيفك للمجموعة أو للحصص الفردية.'
            });
        }

        res.json({
            currency: 'USD',
            plans: groups.map(group => ({
                group_id: group.id,
                group_name: group.name,
                program: group.program,
                monthly_amount: group.program === 'one-on-one'
                    ? 80
                    : 30,
                payment_url: group.program === 'one-on-one'
                    ? 'https://www.paypal.com/ncp/payment/CZJ8EMG4D86R2'
                    : 'https://www.paypal.com/ncp/payment/3YMJPBULYL5CQ'
            }))
        });
    } catch (error) {
        console.error('Payment information failed:', error.code);

        res.status(500).json({
            error: 'تعذر تحميل معلومات الأداء. عاود المحاولة.'
        });
    }
});

app.get('/my-class-sessions', requireStudent, (req, res) => {
    const cutoff = new Date(Date.now() - 40 * 60 * 1000).toISOString();

    const sessions = db.prepare(`
        SELECT
            s.id,
            g.name AS group_name,
            s.starts_at
        FROM class_enrollments e
        JOIN class_groups g ON g.id = e.group_id
        JOIN class_sessions s ON s.group_id = g.id
        WHERE e.student_id = ?
          AND s.starts_at > ?
        ORDER BY s.starts_at ASC, s.id ASC
    `).all(req.student.id, cutoff);

    res.set('Cache-Control', 'no-store');
    res.json({ sessions });
});
app.get('/admin/class-sessions', requireAdmin, (req, res) => {
    const sessions = db.prepare(`
        SELECT
            s.id,
            s.group_id,
            g.name AS group_name,
            s.starts_at
        FROM class_sessions s
        JOIN class_groups g ON g.id = s.group_id
        WHERE s.starts_at >= ?
        ORDER BY s.starts_at ASC, s.id ASC
    `).all(new Date().toISOString());

    res.set('Cache-Control', 'no-store');
    res.json({ sessions });
});
app.get('/admin/class-groups', requireAdmin, (req, res) => {
    const groups = db.prepare(`
        SELECT id, name, program
        FROM class_groups
        ORDER BY id DESC
    `).all();

    res.set('Cache-Control', 'no-store');
    res.json({ groups });
});

app.post('/admin/class-groups', requireAdmin, (req, res) => {
    const name = typeof req.body?.name === 'string'
        ? req.body.name.trim()
        : '';
    const program = req.body?.program;

    if (name.length < 2 || name.length > 80 ||
        !['kids', 'adults', 'one-on-one'].includes(program)) {
        return res.status(400).json({
            error: 'كتبي اسم المجموعة واختاري البرنامج الصحيح.'
        });
    }

    try {
        const result = db.prepare(`
            INSERT INTO class_groups (name, program)
            VALUES (?, ?)
        `).run(name, program);

        res.status(201).json({
            group: {
                id: result.lastInsertRowid,
                name,
                program
            }
        });
    } catch (error) {
        console.error('Class group creation failed:', error.code);
        res.status(500).json({
            error: 'تعذر إنشاء المجموعة. عاودي المحاولة.'
        });
    }
});
app.get('/admin/bookings', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');

    const bookings = db.prepare(`
        SELECT
            b.id,
            b.program,
            b.learner_name,
            b.learner_age,
            b.status,
            b.created_at,
            s.name AS account_name,
            s.email,
            t.starts_at,
            t.ends_at
        FROM bookings b
        JOIN students s ON s.id = b.student_id
        JOIN booking_slots t ON t.id = b.slot_id
        ORDER BY b.created_at DESC, b.id DESC
    `).all();

    res.json({ bookings });
});
app.get('/admin/students', requireAdmin, (req, res) => {
    const students = db.prepare(`
        SELECT
            s.id,
            s.name,
            s.email,
            (
                SELECT COUNT(*)
                FROM lesson_access a
                WHERE a.student_id = s.id
                  AND a.access_type = 'trial'
            ) AS trial_count,
                         (
                SELECT MAX(a.starts_at)
                FROM lesson_access a
                WHERE a.student_id = s.id
                  AND a.access_type = 'trial'
            ) AS trial_starts_at,
            (
                SELECT MAX(a.ends_at)
                FROM lesson_access a
                WHERE a.student_id = s.id
                  AND a.access_type = 'trial'
            ) AS trial_ends_at,
            (
                SELECT MAX(a.ends_at)
                FROM lesson_access a
                WHERE a.student_id = s.id
                  AND a.access_type = 'monthly'
            ) AS paid_until,
(
    SELECT GROUP_CONCAT(a.starts_at)
    FROM lesson_access a
    WHERE a.student_id = s.id
      AND a.access_type = 'monthly'
) AS paid_months
        FROM students s
        ORDER BY s.id DESC
    `).all();

    res.json({ students });
});
app.post('/admin/students/:id/trial', requireAdmin, (req, res) => {
    const studentId = Number(req.params.id);

    if (!Number.isSafeInteger(studentId) || studentId < 1) {
        return res.status(400).json({ error: 'رقم التلميذ غير صحيح' });
    }

    const student = db.prepare(
        'SELECT id FROM students WHERE id = ?'
    ).get(studentId);

    if (!student) {
        return res.status(404).json({ error: 'التلميذ ما لقيناهش' });
    }

    const previousTrial = db.prepare(
        "SELECT id FROM lesson_access WHERE student_id = ? AND access_type = 'trial'"
    ).get(studentId);

    if (previousTrial) {
        return res.status(409).json({ error: 'هاد التلميذ استفاد من التجربة من قبل' });
    }

    const startsAt = new Date();
    const endsAt = new Date(startsAt.getTime() + 2 * 60 * 60 * 1000);

    db.prepare(`
        INSERT INTO lesson_access (student_id, access_type, starts_at, ends_at)
        VALUES (?, 'trial', ?, ?)
    `).run(studentId, startsAt.toISOString(), endsAt.toISOString());

    res.json({ ok: true, ends_at: endsAt.toISOString() });
});
app.post('/admin/students/:id/month', requireAdmin, (req, res) => {
    const studentId = Number(req.params.id);
    const month = String(req.body?.month || '');

    if (!Number.isSafeInteger(studentId) || studentId < 1 ||
        !/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) {
        return res.status(400).json({ error: 'التلميذ أو الشهر غير صحيح' });
    }

    const student = db.prepare(
        'SELECT id FROM students WHERE id = ?'
    ).get(studentId);

    if (!student) {
        return res.status(404).json({ error: 'التلميذ ما لقيناهش' });
    }

    const startsAt = `${month}-01`;
    const [year, number] = month.split('-').map(Number);
    const nextMonth = number === 12
        ? `${year + 1}-01-01`
        : `${year}-${String(number + 1).padStart(2, '0')}-01`;

    const alreadyActive = db.prepare(`
        SELECT id FROM lesson_access
        WHERE student_id = ? AND access_type = 'monthly' AND starts_at = ?
    `).get(studentId, startsAt);

    if (alreadyActive) {
        return res.status(409).json({ error: 'هاد الشهر مفعّل لهاد التلميذ من قبل' });
    }

    db.prepare(`
        INSERT INTO lesson_access (student_id, access_type, starts_at, ends_at)
        VALUES (?, 'monthly', ?, ?)
    `).run(studentId, startsAt, nextMonth);

    res.json({ ok: true, paid_until: nextMonth });
});
app.post('/admin/students/:id/cancel-month', requireAdmin, (req, res) => {
    const studentId = Number(req.params.id);
    const month = String(req.body?.month || '');

    if (!Number.isSafeInteger(studentId) || studentId < 1 ||
        !/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) {
        return res.status(400).json({
            error: 'التلميذ أو الشهر غير صحيح'
        });
    }

    const result = db.prepare(`
        DELETE FROM lesson_access
        WHERE student_id = ?
          AND access_type = 'monthly'
          AND starts_at = ?
    `).run(studentId, `${month}-01`);

    if (result.changes === 0) {
        return res.status(404).json({
            error: 'هاد الشهر ما مفعّلش لهاد التلميذ'
        });
    }

    res.json({ ok: true });
});
function requireLessonAccess(req, res, next) {
    const student = req.student;

    if (!student) {
        return res.status(401).json({
            error: 'خاصك تسجل الدخول أولاً'
        });
    }

    try {
        const admin = db.prepare(
            'SELECT student_id FROM admins WHERE student_id = ?'
        ).get(student.id);

        if (admin) return next();

        const now = new Date();
        const instant = now.toISOString();

        const parts = new Intl.DateTimeFormat('en-US', {
            timeZone: 'Africa/Casablanca',
            year: 'numeric',
            month: '2-digit',
            day: '2-digit'
        }).formatToParts(now);

        const value = type =>
            parts.find(part => part.type === type).value;

        const today =
            `${value('year')}-${value('month')}-${value('day')}`;

        // التجربة السارية كتبقى خدامة.
        const trial = db.prepare(`
            SELECT id FROM lesson_access
            WHERE student_id = ?
              AND access_type = 'trial'
              AND starts_at <= ?
              AND ends_at > ?
            LIMIT 1
        `).get(student.id, instant, instant);

        if (trial) return next();

        // الحصة المنتظمة كتحتاج اشتراكاً ساري المفعول.
        const subscription = db.prepare(`
            SELECT id FROM lesson_access
            WHERE student_id = ?
              AND access_type = 'monthly'
              AND starts_at <= ?
              AND ends_at > ?
            LIMIT 1
        `).get(student.id, today, today);

        if (!subscription) {
            return res.status(403).json({
                error: 'ما عندكش تجربة سارية أو اشتراك شهري مفعّل. راجع حجوزاتك أو تواصل مع الأستاذة.'
            });
        }

        // البداية خاصها تكون وصلات، والنهاية مازال ما دازتش.
        const oldestStart = new Date(
            now.getTime() - 40 * 60 * 1000
        ).toISOString();

        const session = db.prepare(`
            SELECT s.id
            FROM class_sessions s
            JOIN class_enrollments e
                ON e.group_id = s.group_id
            WHERE e.student_id = ?
              AND s.starts_at <= ?
              AND s.starts_at > ?
            LIMIT 1
        `).get(student.id, instant, oldestStart);

        if (!session) {
            return res.status(403).json({
                error: 'ما عندك حتى حصة منتظمة جارية دابا. شوف المواعيد فصفحة «جدول حصصي».'
            });
        }

        return next();
    } catch (error) {
        console.error(
            'Lesson access check failed:',
            error.code || 'ACCESS_CHECK_FAILED'
        );

        return res.status(500).json({
            error: 'تعذر التحقق من صلاحية الدخول. عاود المحاولة.'
        });
    }
}
function requireAdminPage(req, res, next) {
    const student = currentStudent(req);

    if (!student) {
        return res.redirect('/login.html');
    }

    const admin = db.prepare(
        'SELECT student_id FROM admins WHERE student_id = ?'
    ).get(student.id);

    if (!admin) {
        return res.redirect('/index.html');
    }

    req.student = student;
    next();
}
return {
    requireStudent,
    requireStudentPage,
    requireLessonAccess,
    requireAdminPage
};
};
