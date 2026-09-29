import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import crypto from 'crypto';
import Anthropic from '@anthropic-ai/sdk';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const API_KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';
const SESSION_SECRET = process.env.SESSION_SECRET;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5500';
const MAX_FILE_SIZE = 8 * 1024 * 1024;

if (!API_KEY) throw new Error('ANTHROPIC_API_KEY غير موجود في ملف .env');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET يجب أن يكون 32 حرفًا على الأقل');

const anthropic = new Anthropic({ apiKey: API_KEY });
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = file.mimetype === 'application/pdf' || /^image\/(jpeg|png|gif|webp)$/i.test(file.mimetype);
    cb(ok ? null : new Error('يسمح فقط بصورة أو PDF'), ok);
  }
});

const allowedOrigins = ALLOWED_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, cb) {
  if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
  return cb(new Error('Origin غير مسموح'));
}}));
app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (_req, res) => res.json({ ok: true, model: MODEL }));

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unbase64url(input) {
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}
function signSession(studentId) {
  const payload = base64url(JSON.stringify({ sub: studentId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifySession(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const body = JSON.parse(unbase64url(payload));
    if (!body?.sub || !body?.exp || body.exp < Date.now()) return null;
    return body;
  } catch {
    return null;
  }
}
function getBearer(req) {
  const h = req.get('authorization') || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}
function cleanText(value, max = 5000) {
  return String(value ?? '').slice(0, max);
}

app.post('/api/session', (req, res) => {
  const studentId = cleanText(req.body?.studentId, 120);
  if (!/^[a-zA-Z0-9:_-]{8,120}$/.test(studentId)) return res.status(400).json({ error: 'studentId غير صالح' });
  return res.json({ token: signSession(studentId), expiresIn: 7 * 24 * 60 * 60 });
});

const tools = [
  {
    name: 'add_task',
    description: 'أضف مهمة جديدة للمستخدم. استخدمها عندما يطلب بوضوح إنشاء مهمة.',
    input_schema: { type: 'object', additionalProperties: false, properties: {
      title: { type: 'string' }, date: { type: 'string', description: 'YYYY-MM-DD أو اتركها فارغة لليوم' }, time: { type: 'string', description: 'HH:MM أو فارغ' }, duration: { type: 'number' }
    }, required: ['title'] }
  },
  {
    name: 'complete_task',
    description: 'أكمل مهمة موجودة. فضّل id إن كان متاحًا، وإلا استخدم عنوانًا مطابقًا.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'add_note',
    description: 'أنشئ ملاحظة جديدة للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { title: { type: 'string' }, body: { type: 'string' } }, required: ['body'] }
  },
  {
    name: 'add_expense',
    description: 'سجل مصروفًا للمستخدم.',
    input_schema: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' }, amount: { type: 'number' }, category: { type: 'string' } }, required: ['name','amount'] }
  },
  {
    name: 'delete_task',
    description: 'يطلب حذف مهمة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  },
  {
    name: 'delete_note',
    description: 'يطلب حذف ملاحظة. هذا الإجراء حساس ويجب أن يعود للتطبيق كطلب تأكيد ولا ينفذ مباشرة.',
    input_schema: { type: 'object', additionalProperties: false, properties: { id: { type: ['string','number'] }, title: { type: 'string' } } }
  }
];

function buildSystem(context) {
  return `أنت المساعد الذكي الرسمي والشامل داخل تطبيق «مهامي» للطلاب. مهمتك مساعدة المستخدم في احتياجاته الأكاديمية والمالية والشخصية المرتبطة بالتطبيق بدقة واحترافية، مع أسلوب إنساني وودود.\n\n`+
`أسلوب التفاعل:\n`+
`- تحدث بعربية سعودية بسيطة وطبيعية وودودة ومشجعة، وبشكل مباشر من غير حشو أو مبالغة.\n`+
`- نظّم الرد عند الحاجة باستخدام عناوين قصيرة، نقاط، خطوات، أو جداول نصية بسيطة لتكون القراءة سريعة وواضحة.\n`+
`- إذا احتاج المستخدم شرحًا، اشرح ثم أعطِ مثالًا عمليًا قصيرًا عند فائدته.\n`+
`- لا تدّعي تنفيذ شيء لم يتم تنفيذه فعليًا من خلال أداة أو من التطبيق.\n\n`+
`نطاق المعرفة والوصول:\n`+
`- اعتبر بيانات <student_data> هي بيانات المستخدم الحالية التي يزوّدك بها التطبيق، ويمكنك تحليلها والربط بينها والإجابة عن الأسئلة المتعلقة بها.\n`+
`- عند وجود صورة أو PDF مرفق في الطلب، اقرأ محتواه واستخرج منه النص والمعلومات والتمارين والنقاط المهمة قبل الإجابة.\n`+
`- لا تخترع بيانات غير موجودة في سياق الطالب، وإذا كانت معلومة أساسية ناقصة فاذكر ذلك بوضوح واسأل عند الحاجة.\n`+
`- لا تطلب مفاتيح API أو أسرار الخادم أو كلمات المرور.\n\n`+
`المهام الأكاديمية والتعليمية:\n`+
`- ساعد الطلاب من المرحلة المتوسطة والثانوية والجامعة والخريجين، وفي مختلف التخصصات والمواد.\n`+
`- لخّص الدروس والمحاضرات والملفات، واستخرج الأفكار الرئيسية، التعريفات، القوانين، المصطلحات، والأسئلة المتوقعة.\n`+
`- حوّل المحتوى عند الطلب إلى نقاط حفظ سريعة، خطوات، أسئلة وأجوبة، أو خريطة ذهنية نصية.\n`+
`- اشرح الواجبات والمسائل والقواعد والمصطلحات المعقدة بطريقة مبسطة ومتدرجة حسب مستوى الطالب.\n`+
`- عند وجود سؤال دراسي من صورة أو PDF: اقرأه أولًا، ثم حدّد المطلوب، ثم اشرح الحل أو الفكرة بوضوح.\n\n`+
`الإدارة المالية داخل التطبيق:\n`+
`- ساعد في تسجيل المصروفات اليومية وتصنيفها حسب نوعها مثل دراسة، مواصلات، شخصي وغيرها.\n`+
`- استخدم بيانات المصروفات الحالية لإعطاء مجموعات وتقارير وملخصات عند الطلب، مثل مصروف اليوم، حسب التصنيف، أو مقارنة الإنفاق بالميزانية الموجودة في السياق.\n`+
`- لا تغيّر أي مبلغ أو مصروف إلا من خلال أداة التطبيق المخصصة لذلك.\n\n`+
`إدارة بيانات التطبيق:\n`+
`- استخدم الأدوات عندما يريد المستخدم بوضوح إنشاء مهمة، إكمال مهمة، إضافة ملاحظة، أو تسجيل مصروف.\n`+
`- عند عرض مهام اليوم أو الإحصائيات أو المصروفات، اعتمد على البيانات الحالية داخل <student_data> ولا تتوقع أرقامًا من عندك.\n`+
`- عند وجود أكثر من عنصر متشابه، استخدم المعرّف إن كان متاحًا أو اطلب توضيحًا قبل التغيير.\n`+
`- حذف مهمة أو ملاحظة إجراء حساس: استخدم أداة الحذف فقط لإرجاع طلب تأكيد للتطبيق، ولا تنفذ الحذف مباشرة.\n`+
`- إذا كان الطلب غامضًا بطريقة قد تؤدي إلى تعديل خاطئ للبيانات، اسأل سؤالًا واحدًا واضحًا بدل التخمين.\n\n`+
`القاعدة الأساسية: كن مساعدًا عمليًا ودقيقًا، واستفد من كل البيانات الحالية التي أرسلها التطبيق وكل محتوى المرفق في الطلب، مع الحفاظ على حدود الأدوات والصلاحيات السابقة.\n\n`+
`<student_data>${JSON.stringify(context)}</student_data>`;
}

function fileBlock(file) {
  if (!file) return null;
  const data = file.buffer.toString('base64');
  if (file.mimetype === 'application/pdf') {
    return { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data } };
  }
  return { type: 'image', source: { type: 'base64', media_type: file.mimetype, data } };
}

app.post('/api/assistant', upload.single('file'), async (req, res) => {
  try {
    const session = verifySession(getBearer(req));
    if (!session) return res.status(401).json({ error: 'جلسة المساعد غير صالحة أو منتهية' });

    const message = cleanText(req.body?.message, 6000);
    const context = JSON.parse(req.body?.context || '{}');
    if (context.studentId !== session.sub) return res.status(403).json({ error: 'هوية الطالب لا تطابق الجلسة الحالية' });
    if (!message && !req.file) return res.status(400).json({ error: 'اكتب طلبك أو أرفق ملفًا' });

    const content = [];
    const attachment = fileBlock(req.file);
    if (attachment) content.push(attachment);
    content.push({ type: 'text', text: message || 'اشرح لي المرفق، لخّصه، واستخرج أهم النقاط والواجبات منه.' });

    const response = await anthropic.messages.create({
      model: MODEL,
      max_tokens: 1800,
      system: buildSystem(context),
      tools,
      tool_choice: { type: 'auto' },
      messages: [{ role: 'user', content }]
    });

    const textParts = response.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    const toolUse = response.content.find(b => b.type === 'tool_use');

    if (toolUse) {
      if (toolUse.name === 'delete_task' || toolUse.name === 'delete_note') {
        return res.json({ reply: textParts || 'هذا الإجراء يحتاج تأكيدك قبل الحذف.', confirmation: { type: toolUse.name, ...toolUse.input } });
      }
      return res.json({ reply: textParts || 'تمام، بنفذها لك الآن.', action: { type: toolUse.name, ...toolUse.input } });
    }

    return res.json({ reply: textParts || 'أكيد 👍 قل لي وش تبغى أسوي.' });
  } catch (error) {
    console.error(error);
    const message = error?.message || 'تعذر تشغيل المساعد';
    return res.status(500).json({ error: message });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'الملف أكبر من 8MB' });
  if (err?.message) return res.status(400).json({ error: err.message });
  return res.status(500).json({ error: 'خطأ غير متوقع في السيرفر' });
});

app.listen(PORT, () => console.log(`Mahami Claude server running on http://localhost:${PORT} using ${MODEL}`));
