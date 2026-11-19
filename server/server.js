require('dotenv').config();

const express = require('express');
const path = require('path');
const KJUR = require('jsrsasign');
const { rateLimit } = require('express-rate-limit');
const app = express();
app.use(express.json());
const allowedOrigins = new Set([
    'http://127.0.0.1:3000',
    'http://localhost:3000'
]);

if (process.env.PUBLIC_ORIGIN) {
    allowedOrigins.add(new URL(process.env.PUBLIC_ORIGIN).origin);
}

app.use((req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    let sourceOrigin = req.get('Origin');

    if (!sourceOrigin) {
        try {
            sourceOrigin = new URL(req.get('Referer')).origin;
        } catch {
            sourceOrigin = null;
        }
    }

    if (!allowedOrigins.has(sourceOrigin)) {
        return res.status(403).json({
            error: 'مصدر الطلب غير مسموح. افتحي الموقع من الرابط المعتمد.'
        });
    }

    next();
});
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        error: 'محاولات الدخول كثيرة. تسنّى 15 دقيقة وعاود المحاولة.'
    }
});

app.post('/auth/login', loginLimiter);
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
        error: 'محاولات إنشاء الحساب كثيرة. عاود المحاولة من بعد ساعة.'
    }
});

app.post('/auth/register', registerLimiter);

const {
    requireStudent,
    requireStudentPage,
    requireLessonAccess,
    requireAdminPage
} = require('./auth')(app);

app.get(
    ['/room.html', '/mobile-room.html'],
    requireStudentPage,
    (req, res, next) => next()
);

app.get(
    '/admin.html',
    requireAdminPage,
    (req, res, next) => next()
);

app.use(express.static(
    path.join(__dirname, '..', 'boutaina work')
));

const ZOOM_CLIENT_ID = process.env.ZOOM_CLIENT_ID;
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET;
const ZOOM_MEETING_ID = process.env.ZOOM_MEETING_ID;
const ZOOM_MEETING_PASSWORD = process.env.ZOOM_MEETING_PASSWORD;

if (!ZOOM_CLIENT_ID || !ZOOM_CLIENT_SECRET ||
    !ZOOM_MEETING_ID || !ZOOM_MEETING_PASSWORD) {
    throw new Error('Zoom configuration is missing');
}

app.post(
    '/zoom-signature',
    requireStudent,
    requireLessonAccess,
    (req, res) => {
        const meetingNumber = ZOOM_MEETING_ID;
        const iat = Math.floor(Date.now() / 1000) - 30;
        const exp = iat + 60 * 60 * 2;

        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };

        const payload = {
            appKey: ZOOM_CLIENT_ID,
            mn: meetingNumber,
            role: 0,
            iat,
            exp,
            tokenExp: exp
        };

        const signature = KJUR.jws.JWS.sign(
            'HS256',
            JSON.stringify(header),
            JSON.stringify(payload),
            ZOOM_CLIENT_SECRET
        );

        res.set('Cache-Control', 'no-store');

        res.json({
            signature,
            meetingNumber,
            password: ZOOM_MEETING_PASSWORD
        });
    }
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on http://127.0.0.1:${PORT}`);
});