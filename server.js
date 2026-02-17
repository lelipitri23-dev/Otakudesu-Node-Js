/**
* =================================================================================
* SERVER CONFIGURATION & DEPENDENCIES
* =================================================================================
*/
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const compression = require('compression');
const NodeCache = require('node-cache');
const axios = require('axios');
const siteName = process.env.SITE_NAME || 'RajaAnime';


// --- Custom Modules & Utils ---
const {
  slugify,
  formatCompactNumber,
  encodeAnimeSlugs
} = require('./utils/helpers');
const {
  uploadVideoToLewdHost
} = require('./utils/lewdUpload');
const {
  uploadToR2
} = require('./utils/r2Upload');
//const apiV1Routes = require('./routes/api_v1');
// --- Models ---
const Anime = require('./models/Anime');
const Episode = require('./models/Episode');
const Bookmark = require('./models/Bookmark');
const User = require('./models/User');
const Comment = require('./models/Comment');
const Report = require('./models/Report');

// --- Environment Variables & Constants ---
const PORT = process.env.PORT || 3000;
const SITE_NAME = process.env.SITE_NAME || 'RajaAnime';
const SITE_URL = process.env.SITE_URL || `http://localhost:${PORT}`;
const DB_URI = process.env.DB_URI;
const SESSION_SECRET = process.env.SESSION_SECRET || 'secret_key';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const UPLOAD_WEB_PATH = 'images';
const UPLOAD_DISK_PATH = process.env.RENDER_DISK_PATH || path.join(__dirname, 'public', UPLOAD_WEB_PATH);
const ITEMS_PER_PAGE = 20;

// --- Initialize App & Cache ---
const app = express();
const appCache = new NodeCache( {
  stdTTL: 3600
});
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
* =================================================================================
* FILE UPLOAD CONFIGURATION (Multer)
* =================================================================================
*/
// Ensure upload directory exists if using local disk
try {
  if (!process.env.RENDER_DISK_PATH && !fs.existsSync(UPLOAD_DISK_PATH)) {
    fs.mkdirSync(UPLOAD_DISK_PATH, {
      recursive: true
    });
  }
} catch (err) {
  console.log("Info: Gagal membuat folder upload lokal (Aman untuk diabaikan di environment Serverless/Vercel).");
}
app.locals.cleanTitle = (title) => {
  if (!title) return '';
  
  let cleaned = title;

  const patterns = [
    /\s*[\(\[\-\|:]?\s*(Subtitle Indonesia|Sub Indo|Sub lndo)\s*[\)\]]?\s*$/ig,
    /\s*(Sub\s*Indo|Subtitle\s*Indonesia)\s*[:|-]\s*/ig,
    /\s*[\(\[]?\s*Episode\s*[\d\s\–\-\.]+(\s*\(\s*End\s*\))?[\)\]]?/ig,
    /\s+BD\s*$/ig,
    /\s+BD\s+/ig,
    /\s*[\(\[]\s*Batch\s*[\)\]]/ig,
    /\s*Batch\s*/ig
  ];
  patterns.forEach(regex => {
    cleaned = cleaned.replace(regex, '');
  });
  cleaned = cleaned.replace(/\s*[:|-]\s*$/, '');
  return cleaned.replace(/\s+/g, ' ').trim();
};
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg',
    'image/png',
    'image/webp',
    'application/json'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Format file tidak diizinkan!'), false);
  }
};

const upload = multer( {
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024
  } // 5MB Limit
});

/**
* =================================================================================
* MIDDLEWARE SETUP
* =================================================================================
*/

app.use(compression()); // Compress responses
app.use(express.static(path.join(__dirname, 'public'))); // Static public folder
app.use(`/${UPLOAD_WEB_PATH}`, express.static(UPLOAD_DISK_PATH)); // Static images folder
app.get(`/${UPLOAD_WEB_PATH}/:filename`, (req, res) => {
  const filename = req.params.filename;
  
  // Menggunakan 301 agar Google mengupdate indeksnya ke URL baru
  // Pola: http://local/images/nama.jpg -> https://cdn.../anime/nama.jpg
  res.redirect(301, `https://cdn.wibuhub.qzz.io/anime/${filename}`);
});
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

// --- Global Locals (Variables accessible in all views) ---
app.locals.slugify = slugify;
app.locals.formatCompactNumber = formatCompactNumber;
app.locals.siteName = SITE_NAME;
app.locals.SITE_URL = SITE_URL;

// --- Session Setup ---
app.use(session( {
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: DB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60 // 14 Days
  }),
  cookie: {
    secure: IS_PRODUCTION,
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
}));

// --- User Session Middleware ---
app.use((req, res, next) => {
  res.locals.user = req.session.userId ? {
    id: req.session.userId,
    username: req.session.username
  }: null;
  next();
});

// --- Maintenance Mode Middleware ---
app.use((req, res, next) => {
  const isMaintenance = process.env.MAINTENANCE_MODE === 'true';

  // Whitelist paths during maintenance
  const allowedPrefixes = ['/admin', '/login', '/logout', `/${UPLOAD_WEB_PATH}`];
  const isAllowedPath = allowedPrefixes.some(prefix => req.path.startsWith(prefix));

  if (isMaintenance) {
    if (isAllowedPath || req.path === '/maintenance') return next();
    return res.redirect('/maintenance');
  }

  // Prevent accessing maintenance page if not in maintenance mode
  if (!isMaintenance && req.path === '/maintenance') {
    return res.redirect('/');
  }
  next();
});

/**
* =================================================================================
* CUSTOM AUTH & SECURITY MIDDLEWARE
* =================================================================================
*/
const isLoggedIn = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  res.status(401).json({
    error: 'Anda harus login'
  });
};

const isAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) return next();
  res.redirect('/admin/login');
};

async function checkApiReferer(req, res, next) {
  try {
    const referer = req.headers.referer;
    if (!referer) return res.status(403).json({
      error: 'Akses Ditolak'
    });

    const allowedHostname = new URL(SITE_URL).hostname;
    const refererHostname = new URL(referer).hostname;

    if (refererHostname === allowedHostname) {
      next();
    } else {
      return res.status(403).json({
        error: 'Akses Ditolak'
      });
    }
  } catch (error) {
    return res.status(403).json({
      error: 'Akses Ditolak'
    });
  }
}

/**
* =================================================================================
* ROUTES: AUTHENTICATION (ADMIN & USER)
* =================================================================================
*/
// Admin Login
app.get('/admin/login', (req, res) => {
  if (req.session && req.session.isAdmin) return res.redirect('/admin');
  res.render('admin/login', {
    page: 'admin-login', pageTitle: `Admin Login - ${SITE_NAME}`, error: req.query.error,
    pageDescription: '', pageImage: '', pageUrl: '', query: ''
  });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.redirect('/admin/login?error=Invalid credentials');
  }
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/admin/login');
  });
});

// User Auth
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/bookmarks');
  res.render('login', {
    page: 'login', pageTitle: 'Login', error: req.query.error, pageDescription: '', pageImage: '', pageUrl: '', query: ''
  });
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user || !(await user.comparePassword(password))) return res.redirect('/login?error=Invalid credentials');
    req.session.userId = user._id;
    req.session.username = user.username;
    res.redirect('/bookmarks');
  } catch (e) {
    res.redirect(`/login?error=${encodeURIComponent(e.message)}`);
  }
});

app.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/bookmarks');
  res.render('register', {
    page: 'register', pageTitle: 'Register', error: req.query.error, pageDescription: '', pageImage: '', pageUrl: '', query: ''
  });
});

app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (await User.findOne({ username: username.toLowerCase() })) return res.redirect('/register?error=Username taken');
    const user = new User({ username, password });
    await user.save();
    req.session.userId = user._id;
    req.session.username = user.username;
    res.redirect('/bookmarks');
  } catch (e) {
    res.redirect(`/register?error=${encodeURIComponent(e.message)}`);
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/home')));

/**
* =================================================================================
* ROUTES: ADMIN DASHBOARD & MANAGEMENT
* =================================================================================
*/
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const [totalAnime, totalEpisodes, totalUsers, totalComments] = await Promise.all([
      Anime.countDocuments(), Episode.countDocuments(), User.countDocuments(), Comment.countDocuments()
    ]);
    res.render('admin/dashboard', {
      page: 'admin-dashboard', pageTitle: `Admin Dashboard`,
      totalAnime, totalEpisodes, totalUsers, totalComments,
      pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Gagal memuat statistik.');
  }
});

// --- Anime Management ---
app.get('/admin/anime', isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 30;
    const skip = (page - 1) * limit;
    const searchQuery = req.query.search || '';
    const query = searchQuery ? {
      $or: [
        { title: new RegExp(searchQuery, 'i') },
        { pageSlug: new RegExp(searchQuery, 'i') }
      ]
    } : {};

    const [animes, totalCount] = await Promise.all([
      Anime.find(query).sort({ updatedAt: -1 }).skip(skip).limit(limit).lean(),
      Anime.countDocuments(query)
    ]);

    res.render('admin/anime-list', {
      animes, page: 'admin-anime-list', pageTitle: `Admin Anime List`,
      currentPage: page, totalPages: Math.ceil(totalCount / limit),
      baseUrl: searchQuery ? `/admin/anime?search=${encodeURIComponent(searchQuery)}` : '/admin/anime',
      searchQuery, pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Error loading anime list.');
  }
});

app.get('/admin/anime/add', isAdmin, (req, res) => res.render('admin/add-anime', {
  page: 'admin-add', pageTitle: 'Add Anime', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));

app.post('/admin/anime/add', isAdmin, upload.single('animeImage'), async (req, res) => {
  try {
    const formData = req.body;
    if (!formData.title || !formData.pageSlug) return res.status(400).send('Judul/Slug wajib.');
    if (await Anime.findOne({ pageSlug: formData.pageSlug })) return res.status(400).send('Slug sudah ada.');

    let imageUrl = formData.imageUrl || '/images/default.jpg';
    if (req.file) {
      imageUrl = await uploadToR2(req.file.buffer, `${formData.pageSlug}${path.extname(req.file.originalname)}`, req.file.mimetype);
    }

    await Anime.create({
      title: formData.title, pageSlug: formData.pageSlug, imageUrl, synopsis: formData.synopsis,
      info: {
        Alternatif: formData['info.Alternatif'], Type: formData['info.Type'], Status: formData['info.Status'] || 'Unknown',
        Released: formData['info.Released'], Studio: formData['info.Studio'], Producers: formData['info.Producers']
      },
      genres: formData.genres ? formData.genres.split(',').map(g => g.trim()) : [], episodes: []
    });
    res.redirect('/admin/anime');
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/admin/anime/:slug/edit', isAdmin, async (req, res) => {
  try {
    const anime = await Anime.findOne({ pageSlug: decodeURIComponent(req.params.slug) }).lean();
    if (!anime) return res.status(404).send('Anime not found.');
    res.render('admin/edit-anime', {
      anime, page: 'admin-edit-anime', pageTitle: `Edit Anime`, pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Error loading form.');
  }
});

app.post('/admin/anime/:slug/edit', isAdmin, async (req, res) => {
  try {
    const updateData = req.body;
    const dataToUpdate = {
      title: updateData.title,
      alternativeTitle: updateData.alternativeTitle,
      synopsis: updateData.synopsis,
      imageUrl: updateData.imageUrl,
      "info.Status": updateData['info.Status'],
      "info.Released": updateData['info.Released'],
      "info.Type": updateData['info.Type'],
      "info.Studio": updateData['info.Studio'],
      "info.Producers": updateData['info.Producers'],
      genres: updateData.genres ? updateData.genres.split(',').map(g => g.trim()).filter(Boolean) : [],
    };
    // Clean undefined keys
    Object.keys(dataToUpdate).forEach(key => (dataToUpdate[key] === undefined || dataToUpdate[key] === '') && delete dataToUpdate[key]);

    await Anime.findOneAndUpdate({ pageSlug: decodeURIComponent(req.params.slug) }, { $set: dataToUpdate }, { new: true });
    res.redirect('/admin/anime');
  } catch (error) {
    res.status(500).send('Error updating.');
  }
});

app.post('/admin/anime/:slug/delete', isAdmin, async (req, res) => {
  try {
    const pageSlug = decodeURIComponent(req.params.slug);
    const anime = await Anime.findOne({ pageSlug }).lean();
    if (!anime) return res.status(404).send('Not found');

    await Episode.deleteMany({ animeSlug: pageSlug });
    await Anime.deleteOne({ pageSlug });
    if (anime.episodes) {
      const epIds = anime.episodes.map(e => e._id);
      await Comment.deleteMany({ episode: { $in: epIds } });
    }
    res.redirect('/admin/anime');
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// --- Episode Management (In Anime Context) ---
app.post('/admin/anime/:slug/episodes/add', isAdmin, async (req, res) => {
  const parentPageSlug = decodeURIComponent(req.params.slug);
  try {
    const { episodeTitle, episodeSlug, episodeDate } = req.body;
    
    // [FIX] Validasi Anime Induk
    const parentAnime = await Anime.findOne({ pageSlug: parentPageSlug });
    if (!parentAnime) return res.status(404).send('Anime tidak ditemukan.');

    // [FIX] Auto-Generate Full Slug: "anime-slug-episode-1"
    // Mencegah duplikat jika user hanya input "1"
    let finalSlug = episodeSlug;
    if (!finalSlug.includes(parentPageSlug)) {
        // Bersihkan input user agar aman di URL
        const cleanSuffix = episodeSlug.replace(/[^a-zA-Z0-9-]/g, '-').replace(/^-+|-+$/g, '');
        finalSlug = `${parentPageSlug}-episode-${cleanSuffix}`;
    }

    // Cek duplikasi slug di database
    if (await Episode.findOne({ episodeSlug: finalSlug })) {
        return res.status(400).send(`Slug Episode sudah ada: ${finalSlug}`);
    }

    const createdEpisode = await Episode.create({
      episodeSlug: finalSlug, 
      title: episodeTitle, 
      streaming: [], 
      downloads: [], 
      thumbnailUrl: '/images/default_thumb.jpg',
      animeTitle: parentAnime.title, 
      animeSlug: parentAnime.pageSlug, 
      animeImageUrl: parentAnime.imageUrl
    });

    await Anime.updateOne({ pageSlug: parentPageSlug }, {
      $push: {
        episodes: {
          title: episodeTitle, 
          url: finalSlug, 
          date: episodeDate || new Date().toLocaleDateString('id-ID'), 
          _id: createdEpisode._id
        }
      }
    });
    
    res.redirect(`/admin/anime/${encodeURIComponent(parentPageSlug)}/edit`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Gagal menambah episode: ' + error.message);
  }
});

// --- Episode List & Edit (Global) ---
app.get('/admin/episodes', isAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 30;
    const skip = (page - 1) * limit;
    const [episodes, totalCount] = await Promise.all([
      Episode.find().sort({ updatedAt: -1 }).skip(skip).limit(limit).lean(),
      Episode.countDocuments()
    ]);
    res.render('admin/episode-list', {
      episodes, page: 'admin-episode-list', pageTitle: `Admin Episodes`,
      currentPage: page, totalPages: Math.ceil(totalCount / limit), baseUrl: '/admin/episodes',
      pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Error loading list.');
  }
});

// [FIX] Menggunakan wildcard (*) agar slug panjang terbaca
app.get('/admin/episode/:slug(*)/edit', isAdmin, async (req, res) => {
  try {
    // [FIX] Hapus paksaan "/" di depan decodeURIComponent
    // Agar bisa membaca slug baik format "/slug" maupun "slug"
    const rawSlug = req.params.slug;
    const episodeSlug = decodeURIComponent(rawSlug);

    // Cari episode (coba cari exact, kalau tidak ketemu coba tambah slash)
    let episode = await Episode.findOne({ episodeSlug }).lean();
    if (!episode) {
        episode = await Episode.findOne({ episodeSlug: `/${episodeSlug}` }).lean();
    }

    if (!episode) return res.status(404).send(`Episode not found (Slug: ${episodeSlug})`);

    res.render('admin/edit-episode', {
      episode, page: 'admin-edit-episode', pageTitle: `Edit Episode`, pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Error loading form.');
  }
});

app.post('/admin/episode/:slug(*)/edit', isAdmin, async (req, res) => {
  try {
    // [FIX] Gunakan logic yang sama untuk decoding
    const rawSlug = req.params.slug;
    const episodeSlug = decodeURIComponent(rawSlug);

    // Pastikan kita update dokumen yang benar (handle slash optional)
    const filter = { 
        $or: [{ episodeSlug: episodeSlug }, { episodeSlug: `/${episodeSlug}` }] 
    };

    const formData = req.body;
    const dataToUpdate = {
      title: formData.title,
      thumbnailUrl: formData.thumbnailUrl,
      updatedAt: new Date()
    };

    dataToUpdate.streaming = (formData.streams || []).filter(s => s.name && s.url).map(s => ({
      name: s.name.trim(), url: s.url.trim()
    }));
    dataToUpdate.downloads = (formData.downloads || []).filter(q => q.quality && q.links.length).map(q => ({
      quality: q.quality.trim(), links: q.links.filter(l => l.host && l.url).map(l => ({
        host: l.host.trim(), url: l.url.trim()
      }))
    }));

    await Episode.findOneAndUpdate(filter, { $set: dataToUpdate }, { new: true, runValidators: true });
    res.redirect('/admin/episodes');
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post('/admin/episode/:slug(*)/delete', isAdmin, async (req, res) => {
  try {
    // [FIX] Perbaikan logic delete agar tidak 404
    const rawSlug = req.params.slug;
    const episodeSlug = decodeURIComponent(rawSlug);
    
    // 1. Cari dulu episode aslinya untuk memastikan slug yang tepat
    let episode = await Episode.findOne({ 
        $or: [{ episodeSlug: episodeSlug }, { episodeSlug: `/${episodeSlug}` }] 
    });

    if (!episode) return res.status(404).send('Episode tidak ditemukan di database.');
    
    // Gunakan slug asli dari database untuk penghapusan yang akurat
    const realSlug = episode.episodeSlug;

    // 2. Hapus Episode
    await Episode.deleteOne({ _id: episode._id });

    // 3. Hapus Referensi di Anime Induk
    await Anime.updateOne(
        { "episodes.url": realSlug }, 
        { $pull: { episodes: { url: realSlug } } }
    );

    // 4. Hapus Komentar terkait
    await Comment.deleteMany({ episode: episode._id });

    res.redirect('/admin/episodes');
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// --- Reports & Tools ---
app.get('/admin/reports', isAdmin, async (req, res) => {
  try {
    const reports = await Report.find().populate('user', 'username').sort({
      createdAt: -1
    }).lean();
    res.render('admin/reports', {
      reports, page: 'admin-reports', pageTitle: 'Laporan Error', pageDescription: '', pageImage: '', pageUrl: '', query: ''
    });
  } catch (error) {
    res.status(500).send('Gagal memuat laporan.');
  }
});

app.post('/admin/report/delete/:id', isAdmin, async (req, res) => {
  try {
    await Report.findByIdAndDelete(req.params.id);
    res.redirect('/admin/reports');
  } catch (error) {
    res.status(500).send('Gagal.');
  }
});

app.get('/admin/backup', isAdmin, (req, res) => res.render('admin/backup', {
  page: 'admin-backup', pageTitle: 'Backup', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));

app.get('/admin/backup/export', isAdmin, async (req, res) => {
  try {
    const fileName = `backup_${SITE_NAME.toLowerCase()}_${new Date().toISOString().split('T')[0]}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);

    res.write(`{ "exportedAt": "${new Date().toISOString()}", "collections": {`);
    const streamCollection = async (model, collectionName) => {
      res.write(`"${collectionName}": [`);
      const cursor = model.find().lean().cursor();
      let first = true;
      for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
        if (!first) res.write(',');
        res.write(JSON.stringify(doc));
        first = false;
      }
      res.write(`]`);
    };

    await streamCollection(Anime, 'animes'); res.write(',');
    await streamCollection(Episode, 'episodes'); res.write(',');
    await streamCollection(Bookmark, 'bookmarks'); res.write(',');
    await streamCollection(User, 'users'); res.write(',');
    await streamCollection(Comment, 'comments');

    res.write(`} }`);
    res.end();
  } catch (error) {
    res.status(500).send('Gagal mengekspor data.');
  }
});

app.post('/admin/backup/import', isAdmin, upload.single('backupFile'), async (req, res) => {
  try {
    if (!req.file || req.file.mimetype !== 'application/json') return res.status(400).send('File harus .json');
    const backupData = JSON.parse(req.file.buffer.toString('utf8'));
    const {
      animes,
      episodes,
      bookmarks,
      users,
      comments
    } = backupData.collections;

    await Promise.all([
      Anime.deleteMany({}), Episode.deleteMany({}), Bookmark.deleteMany({}), User.deleteMany({}), Comment.deleteMany({})
    ]);

    await Promise.all([
      Anime.insertMany(animes), Episode.insertMany(episodes),
      (bookmarks?.length) ? Bookmark.insertMany(bookmarks): Promise.resolve(),
      (users?.length) ? User.insertMany(users): Promise.resolve(),
      (comments?.length) ? Comment.insertMany(comments): Promise.resolve()
    ]);

    res.send('Impor Berhasil! <a href="/admin">Kembali</a>');
  } catch (error) {
    res.status(500).send('Gagal impor: ' + error.message);
  }
});

// Admin Tools Pages
app.get('/admin/batch-upload', isAdmin, (req, res) => res.render('admin/batch-upload', {
  page: 'admin', pageTitle: 'Batch Upload', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));
app.get('/admin/clear-mirrors', isAdmin, (req, res) => res.render('admin/clear-mirrors', {
  page: 'admin', pageTitle: 'Clear Mirrors', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));

/**
* =================================================================================
* ROUTES: ADMIN API (INTERNAL TOOLS)
* =================================================================================
*/
app.post('/admin/api/remote-upload-lewd', isAdmin, async (req, res) => {
  req.setTimeout(30 * 60 * 1000);
  const {
    episodeSlug,
    videoUrl
  } = req.body;
  if (!episodeSlug || !videoUrl) return res.status(400).json({
    success: false, error: 'Data kurang'
  });
  try {
    const newLewdUrl = await uploadVideoToLewdHost(videoUrl);
    const newStreamLink = {
      name: "LewdHost",
      url: newLewdUrl
    };
    await Episode.findOneAndUpdate({
      episodeSlug
    }, {
      $push: {
        streaming: newStreamLink
      }
    }, {
      new: true
    });
    res.json({
      success: true, newLink: newStreamLink
    });
  } catch (error) {
    res.status(500).json({
      success: false, error: error.message
    });
  }
});

app.post('/admin/api/remote-upload', isAdmin, delay, async (req, res) => {
  const {
    episodeSlug,
    videoUrl
  } = req.body;
  const DOOD_API_KEY = process.env.DOOD_API_KEY;
  if (!episodeSlug || !videoUrl || !DOOD_API_KEY) return res.status(400).json({
    success: false, error: 'Data kurang'
  });

  try {
    const doodRes = await axios.get(`https://doodapi.co/api/upload/url?key=${DOOD_API_KEY}&url=${encodeURIComponent(videoUrl)}`);
    if (doodRes.data.status !== 200 || !doodRes.data.result) throw new Error('DoodAPI Error');

    const fileCode = doodRes.data.result.filecode;
    const newStreamLink = {
      name: "Mirror",
      url: `https://dsvplay.com/e/${fileCode}`
    };
    const newDownloadLink = {
      host: "DoodStream",
      url: `https://dsvplay.com/d/${fileCode}`
    };

    await Episode.findOneAndUpdate({
      episodeSlug
    }, {
      $push: {
        streaming: newStreamLink, downloads: {
          quality: "480p", links: [newDownloadLink]
        }
      }
    }, {
      new: true
    });
    res.json({
      success: true, newLink: newStreamLink
    });
  } catch (error) {
    res.status(500).json({
      success: false, error: error.message
    });
  }
});

app.post('/admin/api/clear-mirrors-start', isAdmin, async (req, res) => {
  try {
    const result = await Episode.updateMany({}, {
      $pull: {
        streaming: {
          name: {
            $in: ["Mirror", "Viplay", "EarnVids"]
          }
        },
        downloads: {
          quality: {
            $in: ["Mirror", "Viplay", "EarnVids", "480p", "720p"]
          }
        }
      }
    });
    res.json({
      success: true, modifiedCount: result.modifiedCount
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

/**
* =================================================================================
* ROUTES: PUBLIC (FRONTEND)
* =================================================================================
*/
// [UPDATE] Home Page / Landing Page dengan Data Trending
app.get('/', async (req, res) => {
  try {
    // Ambil 12 Anime Trending berdasarkan View Terbanyak
    const trendingAnime = await Anime.find()
      .sort({ viewCount: -1 })
      .limit(12)
      .select('pageSlug imageUrl title info.Type info.Status viewCount')
      .lean();

    res.render('landing', {
      page: 'landing', 
      // Gunakan 'siteName' (sesuai definisi di atas file), bukan 'SITE_NAME'
      pageTitle: `${siteName} - Nonton Anime Terbaru 2025 Sub Indo`, 
      pageDescription: 'Nonton anime terbaru 2025 sub Indo dari berbagai macam genre yang menarik. Streaming anime Jepang seperti Jujutsu Kaisen, Detective Conan, dan Boruto.', 
      pageImage: `${SITE_URL}/images/default.jpg`, 
      pageUrl: SITE_URL, 
      query: '',
      // Hapus 'SITE_NAME: SITE_NAME' karena sudah otomatis ada di app.locals.siteName
      trendingAnime: encodeAnimeSlugs(trendingAnime) // Kirim data ke view
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error loading landing page');
  }
});


// Home Page
app.get('/', (req, res) => res.render('landing', {
  page: 'landing', pageTitle: SITE_NAME, pageDescription: '', pageImage: `${SITE_URL}/images/default.jpg`, pageUrl: SITE_URL, query: ''
}));

app.get('/home', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const LIMIT = 20; 
    const skip = (page - 1) * LIMIT;
    const [episodes, totalCount, latestSeries] = await Promise.all([
      Episode.find().sort({ _id: -1 }).skip(skip).limit(LIMIT).lean(),
      Episode.countDocuments(),
      Anime.find().sort({ createdAt: -1 }).limit(12).select('pageSlug imageUrl title info.Type info.Released info.Status').lean()
    ]);
    let dynamicTitle = SITE_NAME;
    if (page > 1) {
        dynamicTitle = `${SITE_NAME} - Halaman ${page}`;
    }
    res.render('home', {
      page: 'home',
      pageTitle: dynamicTitle, 
      pageDescription: 'Tempat Download dan Nonton Anime Subtitle Indonesia, dengan Format Mp4 dan MKV.',
      pageImage: `${SITE_URL}/images/default.jpg`,
      pageUrl: `${SITE_URL}${req.originalUrl}`,
      episodes: episodes.map(ep => ({
        watchUrl: `/episode/${ep.episodeSlug}`,
        title: ep.title,
        imageUrl: ep.imageUrl || ep.animeImageUrl || '/images/default.jpg',
        quality: 'HD',
        year: ep.updatedAt ? new Date(ep.updatedAt).getFullYear() : new Date().getFullYear(),
        createdAt: ep.updatedAt || ep.createdAt
      })),
      latestSeries,
      currentPage: page,
      totalPages: Math.ceil(totalCount / LIMIT),
      baseUrl: '/home'
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server Error");
  }
});

app.get('/trending', async (req, res) => {
  try {
    const animes = await Anime.find().sort({
      viewCount: -1
    }).limit(20).lean();
    res.render('trending', {
      animes: encodeAnimeSlugs(animes), page: 'trending', pageTitle: `Anime Trending - ${SITE_NAME}`,
      pageDescription: 'Kumpulan anime yang banyak di tonton dengan subtitle Indonesia', pageImage: `${SITE_URL}/images/default.jpg`, pageUrl: `${SITE_URL}/trending`, totalCount: animes.length
    });
  } catch (e) {
    res.status(500).send('Error.');
  }
});

app.get('/jadwal', (req, res) => res.render('jadwal', {
  page: 'jadwal', pageTitle: `Jadwal Rilis- ${SITE_NAME}`, pageDescription: 'Jadwal anime sub indo yang akan datang di Hunter No Sekai', pageImage: `${SITE_URL}/images/default.jpg`, pageUrl: SITE_URL + req.originalUrl
}));

app.get('/search', async (req, res) => {
  try {
    const q = req.query.q;
    const page = parseInt(req.query.page) || 1;
    if (!q) return res.redirect('/');

    const query = {
      title: new RegExp(q, 'i')
    };
    const [animes,
      totalCount] = await Promise.all([
        Anime.find(query).sort({
          _id: -1
        }).skip((page - 1) * ITEMS_PER_PAGE).limit(ITEMS_PER_PAGE).lean(),
        Anime.countDocuments(query)
      ]);

    const titleSuffix = page > 1 ? ` - Halaman ${page}`: '';
    res.render('list', {
      animes: encodeAnimeSlugs(animes), pageTitle: `Cari: ${q}${titleSuffix} - ${SITE_NAME}`, query: q,
      page: 'list', pageDescription: '', pageImage: '', pageUrl: SITE_URL + `/search?q=${encodeURIComponent(q)}`,
      currentPage: page, totalPages: Math.ceil(totalCount / ITEMS_PER_PAGE), baseUrl: `/search?q=${encodeURIComponent(q)}`, totalCount
    });
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.get('/anime-list', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const [animes,
      totalCount,
      latestSeries] = await Promise.all([
        Anime.find().sort({
          _id: 1
        }).skip((page - 1) * ITEMS_PER_PAGE).limit(ITEMS_PER_PAGE).lean(),
        Anime.countDocuments(),
        Anime.find().sort({
          createdAt: -1
        }).limit(12).select('pageSlug imageUrl title info.Type info.Released info.Status').lean()
      ]);

    const titleSuffix = page > 1 ? ` - Halaman ${page}`: '';
    res.render('anime-list', {
      animes: encodeAnimeSlugs(animes), page: 'anime-list', pageTitle: `Anime List${titleSuffix} - ${SITE_NAME}`,
      pageDescription: `Kumpulan Anime Subtitle Indonesia Terbaru di ${SITE_NAME}.`, pageImage: '',
      pageUrl: SITE_URL + `/anime-list${page > 1 ? `?page=${page}`: ''}`,
      currentPage: page, totalPages: Math.ceil(totalCount / ITEMS_PER_PAGE), baseUrl: '/anime-list', totalCount, latestSeries: encodeAnimeSlugs(latestSeries)
    });
  } catch (e) {
    res.status(500).send(e.message);
  }
});

// --- Dynamic Categories (Genre, Status, Type, Studio, Year) ---
const dynamicListHandler = async (req, res, type, field, paramName, titlePrefix) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const slugVal = req.params[paramName];

    // Cache logic for distinct values
    const cacheKey = `all${type}`;
    let allValues = appCache.get(cacheKey);
    if (!allValues) {
      allValues = await Anime.distinct(field);
      appCache.set(cacheKey, allValues);
    }

    // Match slug to original value
    const originalValue = type === 'Released' ? slugVal: allValues.find(v => slugify(v) === slugVal);
    if (!originalValue) return res.status(404).send(`${type} not found`);

    const query = {
      [field]: new RegExp(type === 'Released' ? originalValue: `^${originalValue}$`, 'i')
    };
    const [animes,
      totalCount] = await Promise.all([
        Anime.find(query).sort({
          _id: -1
        }).skip((page - 1) * ITEMS_PER_PAGE).limit(ITEMS_PER_PAGE).lean(),
        Anime.countDocuments(query)
      ]);

    const titleSuffix = page > 1 ? ` - Halaman ${page}`: '';
    res.render('list', {
      animes: encodeAnimeSlugs(animes), pageTitle: `${titlePrefix}: ${originalValue}${titleSuffix} - ${SITE_NAME}`,
      query: '', page: 'list', pageDescription: `${titlePrefix} ${originalValue} Anime Sub Indo.`, pageImage: '',
      pageUrl: SITE_URL + `/${req.route.path.split('/')[1]}/${slugVal}`,
      currentPage: page, totalPages: Math.ceil(totalCount / ITEMS_PER_PAGE), baseUrl: `/${req.route.path.split('/')[1]}/${slugVal}`, totalCount
    });
  } catch (e) {
    res.status(500).send(e.message);
  }
};

app.get('/genre/:genreSlug', (req, res) => dynamicListHandler(req, res, 'Genres', 'genres', 'genreSlug', 'Genre'));
app.get('/status/:statusSlug', (req, res) => dynamicListHandler(req, res, 'Statuses', 'info.Status', 'statusSlug', 'Status'));
app.get('/type/:typeSlug', (req, res) => dynamicListHandler(req, res, 'Types', 'info.Type', 'typeSlug', 'Type'));
app.get('/studio/:studioSlug', (req, res) => dynamicListHandler(req, res, 'Studios', 'info.Studio', 'studioSlug', 'Studio'));
app.get('/tahun/:year', (req, res) => dynamicListHandler(req, res, 'Released', 'info.Released', 'year', 'Tahun'));

app.get('/genre-list', async (req, res) => {
  let genres = appCache.get('allGenres') || await Anime.distinct('genres');
  appCache.set('allGenres', genres);
  res.render('genre-list', {
    genres: genres.sort(), page: 'genre-list', pageTitle: 'Genre List', pageDescription: '', pageImage: '', pageUrl: ''
  });
});

app.get('/tahun-list', async (req, res) => {
  let dates = appCache.get('allReleasedDates') || await Anime.distinct('info.Released');
  appCache.set('allReleasedDates', dates);
  const years = [...new Set(dates.map(d => d.match(/(\d{4})/) ? d.match(/(\d{4})/)[1]: null).filter(Boolean))].sort((a, b) => b - a);
  res.render('tahun-list', {
    years, page: 'tahun-list', pageTitle: 'Tahun Rilis', pageDescription: '', pageImage: '', pageUrl: '', totalCount: years.length
  });
});

// Anime Detail
app.get('/anime/:slug', async (req, res) => {
  try {
    const pageSlug = decodeURIComponent(req.params.slug);
    const [animeData, recommendations, latestSeries] = await Promise.all([
      Anime.findOne({ pageSlug }).lean(),
      Anime.aggregate([{ $match: { pageSlug: { $ne: pageSlug } } }, { $sample: { size: 8 } }]),
      Anime.find().sort({ createdAt: -1 }).limit(12).select('pageSlug imageUrl title info.Type info.Released info.Status').lean()
    ]);

    if (!animeData) return res.status(404).render('404', { page: '404', pageTitle: '404', pageDescription: '', pageImage: '', pageUrl: '', query: '' });
    
    Anime.updateOne({ pageSlug }, { $inc: { viewCount: 1 } }, { timestamps: false }).exec().catch(() => {});

    // PERBAIKAN LINK: List episode di halaman detail juga diarahkan ke /episode/
    animeData.episodes = animeData.episodes?.map(ep => ({
      ...ep, url: `/episode/${ep.url}` // <-- Fix disini
    })) || [];

    res.render('anime', {
      data: animeData, recommendations, latestSeries,
      page: 'anime', pageTitle: `${animeData.title} Subtitle Indonesia`,
      pageDescription: `Download, Nonton, & Streaming Anime ${animeData.title} Sub Indo resolusi 360p, 480p, 720p lengkap beserta Batch format Mp4 dan Mkv.`,
      pageImage: animeData.imageUrl, pageUrl: SITE_URL + req.originalUrl
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get('/episode/:slug', async (req, res) => {
  try {
    // Gunakan decodeURIComponent agar slug dengan karakter spesial terbaca
    const episodeSlug = decodeURIComponent(req.params.slug); 
    
    // 1. Ambil Data (Episode, Parent Anime, Rekomendasi, Latest)
    const [episodeData, parentAnime, recommendations, latestSeries] = await Promise.all([
      // Coba cari slug apa adanya, ATAU dengan slash di depan (jika format DB beda)
      Episode.findOne({ 
        $or: [{ episodeSlug: episodeSlug }, { episodeSlug: `/${episodeSlug}` }] 
      }).lean(),
      Anime.findOne({ "episodes.url": episodeSlug }).lean(),
      Anime.aggregate([{ $sample: { size: 8 } }]),
      Anime.find({}).sort({ createdAt: -1 }).limit(12).select('pageSlug imageUrl title info.Type info.Released info.Status').lean()
    ]);

    // 2. Jika Episode tidak ditemukan, 404
    if (!episodeData) {
      return res.status(404).render('404', { 
        page: '404', pageTitle: 'Not Found', 
        pageDescription: '', pageImage: '', pageUrl: '', query: '' 
      });
    }
    Episode.updateOne(
      { _id: episodeData._id }, 
      { 
        $set: { lastActive: new Date() },
        $inc: { viewCount: 1 }
      }
    ).exec();
    if (parentAnime) {
      Anime.updateOne(
        { _id: parentAnime._id }, 
        { $inc: { viewCount: 1 } }, 
        { timestamps: false }
      ).exec().catch(() => {});
    }
    if (episodeData.streaming) {
      episodeData.streaming = episodeData.streaming.map(s => ({
        ...s,
        url: s.url ? Buffer.from(s.url).toString('base64') : null
      }));
    }
    if (episodeData.downloads) {
      episodeData.downloads = episodeData.downloads.map(q => ({
        ...q,
        links: q.links.map(l => ({
          ...l,
          url: l.url ? Buffer.from(l.url).toString('base64') : null
        }))
      }));
    }
    const nav = { prev: null, next: null, all: null };
    if (parentAnime) {
      nav.all = `/anime/${parentAnime.pageSlug}`;
      const cleanSlug = episodeSlug.replace(/^\//, ''); 
      
      const idx = parentAnime.episodes.findIndex(ep => {
        return ep.url === cleanSlug || ep.url === `/${cleanSlug}` || ep.url === episodeSlug;
      });
      
      if (idx !== -1) {
        if (idx > 0) {
          let prevUrl = parentAnime.episodes[idx - 1].url;
          if (!prevUrl.startsWith('/')) prevUrl = '/' + prevUrl; // Normalisasi link
          nav.prev = { 
            ...parentAnime.episodes[idx - 1], 
            url: `/episode${prevUrl}`.replace('//', '/') // Cegah double slash
          };
        }
        if (idx < parentAnime.episodes.length - 1) {
          let nextUrl = parentAnime.episodes[idx + 1].url;
          if (!nextUrl.startsWith('/')) nextUrl = '/' + nextUrl;
          nav.next = { 
            ...parentAnime.episodes[idx + 1], 
            url: `/episode${nextUrl}`.replace('//', '/')
          };
        }
      }
    }

    // 6. Render View
    res.render('nonton', {
      data: episodeData, nav, recommendations, latestSeries, parentAnime,
      page: 'nonton', 
      pageTitle: `${episodeData.title}`,
      pageDescription: `Download, Nonton, & Streaming ${episodeData.title} resolusi 360p, 480p, 720p lengkap beserta Batch format Mp4 dan Mkv.`,
      pageImage: parentAnime?.imageUrl || '/images/default.jpg', 
      pageUrl: SITE_URL + req.originalUrl
    });

  } catch (error) {
    console.error("Error di route episode:", error);
    res.status(500).send("Terjadi kesalahan pada server.");
  }
});


app.get('/player', (req, res) => res.render('player', {
  layout: false
}));
app.get('/random', async (req, res) => {
  const randomAnime = await Anime.aggregate([{
    $sample: {
      size: 1
    }
  }]);
  res.redirect(randomAnime[0]?.pageSlug ? `/anime/${encodeURIComponent(randomAnime[0].pageSlug)}`: '/');
});

// --- Legacy Redirects ---
app.get('/category/:slug', (req, res) => res.redirect(301, `/anime/${req.params.slug}`));
app.get('/Anime/:slug', (req, res) => res.redirect(301, `/anime/${req.params.slug}`));
app.get('/trending/page/:page', (req, res) => res.redirect(301, '/trending'));
app.get('/anime-list/', (req, res) => res.redirect(301, '/anime-list'));
app.get('/nonton/:slug', (req, res) => {
  const match = req.params.slug.match(/^(.+)-episode-(\d+)$/i);
  res.redirect(301, match ? `/anime/${match[1]}/${match[2]}`: '/');
});
app.get(/^\/(.+)-episode-(\d+)-subtitle-indonesia\/?$/, (req, res) => res.redirect(301, `/anime/${req.params[0]}/${parseInt(req.params[1], 10)}`));

app.get('/safelink', (req, res) => {
  if (!req.query.url) return res.status(404).render('404', {
    page: '404', pageTitle: '404', pageDescription: '', pageImage: '', pageUrl: '', query: ''
  });
  res.render('safelink', {
    page: 'safelink', pageTitle: 'Redirecting...', pageDescription: '', pageImage: '', pageUrl: '', query: '', base64Url: req.query.url
  });
});

/**
* =================================================================================
* ROUTES: USER BOOKMARKS & API
* =================================================================================
*/
app.get('/bookmarks', (req, res) => res.render('bookmarks', {
  animes: [], page: 'bookmarks', pageTitle: 'Bookmarks', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));

app.get('/api/search', async (req, res) => {
  try {
    if (!req.query.q) return res.json([]);
    const animes = await Anime.find({
      title: new RegExp(req.query.q, 'i')
    }).sort({
      _id: -1
    }).limit(5).select('title pageSlug imageUrl info.Type info.Status').lean();
    res.json(animes);
  } catch (e) {
    res.json([]);
  }
});

app.post('/api/report-error', isLoggedIn, async (req, res) => {
  try {
    await Report.create({
      pageUrl: req.body.pageUrl, message: req.body.message, user: req.session.userId, status: 'Baru'
    });
    res.status(201).json({
      success: true
    });
  } catch (e) {
    res.status(500).json({
      success: false
    });
  }
});

app.use('/api/tahun-ini', checkApiReferer);
app.get('/api/tahun-ini', async (req, res) => {
  const cached = appCache.get('api_tahun_ini');
  if (cached) return res.json(cached);
  try {
    const animes = await Anime.find({
      'info.Released': new RegExp(new Date().getFullYear().toString())
    }).sort({
      createdAt: -1
    }).limit(6).select('pageSlug imageUrl title genres').lean();
    appCache.set('api_tahun_ini', animes);
    res.json(animes);
  } catch (e) {
    res.status(500).json({
      error: 'Error'
    });
  }
});

app.use('/api/now-watching', checkApiReferer);
app.get('/api/now-watching', async (req, res) => {
  try {
    // Ambil 6 episode yang memiliki field 'lastActive', diurutkan dari yang paling baru
    let episodes = await Episode.find({ lastActive: { $exists: true } })
      .sort({ lastActive: -1 })
      .limit(6)
      .select('title episodeSlug animeImageUrl animeTitle lastActive')
      .lean();

    // FALLBACK: Jika fitur ini baru dipasang (belum ada yang nonton), 
    // ambil data berdasarkan 'updatedAt' (Episode baru upload) agar list tidak kosong.
    if (episodes.length < 1) {
       episodes = await Episode.find()
        .sort({ updatedAt: -1 })
        .limit(6)
        .select('title episodeSlug animeImageUrl animeTitle updatedAt as lastActive') // Alias agar kompatibel
        .lean();
    }

    // Set cache sangat singkat (misal 5 detik) agar terasa real-time
    res.setHeader('Cache-Control', 'public, max-age=5'); 
    res.json(episodes);
  } catch (e) {
    res.status(500).json({ error: 'Error' });
  }
});


// Bookmark APIs
app.get('/api/bookmark-status', async (req, res) => {
  try {
    const {
      userId,
      animeId
    } = req.query;
    if (!userId || !mongoose.Types.ObjectId.isValid(animeId)) return res.json({
      isBookmarked: false
    });
    const bookmark = await Bookmark.findOne({
      userId, animeRef: animeId
    });
    res.json({
      isBookmarked: !!bookmark
    });
  } catch (e) {
    res.status(500).json({
      isBookmarked: false
    });
  }
});

app.post('/api/bookmarks', async (req, res) => {
  try {
    const {
      userId,
      animeId
    } = req.body;
    await Bookmark.findOneAndUpdate({
      userId, animeRef: animeId
    }, {
      $setOnInsert: {
        userId, animeRef: animeId
      }
    }, {
      upsert: true
    });
    res.json({
      success: true, isBookmarked: true
    });
  } catch (e) {
    res.status(500).json({
      success: false
    });
  }
});

app.delete('/api/bookmarks', async (req, res) => {
  try {
    const {
      userId,
      animeId
    } = req.query;
    await Bookmark.deleteOne({
      userId, animeRef: animeId
    });
    res.json({
      success: true, isBookmarked: false
    });
  } catch (e) {
    res.status(500).json({
      success: false
    });
  }
});

app.get('/api/my-bookmarks', async (req, res) => {
  try {
    if (!req.query.userId) return res.json([]);
    const bookmarks = await Bookmark.find({
      userId: req.query.userId
    }).populate('animeRef', 'title pageSlug imageUrl episodes info.Released info.Status').sort({
      createdAt: -1
    }).lean();
    res.json(encodeAnimeSlugs(bookmarks.map(b => b.animeRef).filter(Boolean)));
  } catch (e) {
    res.status(500).json({
      error: 'Error'
    });
  }
});

app.delete('/api/bookmarks/all', async (req, res) => {
  try {
    await Bookmark.deleteMany({
      userId: req.query.userId
    });
    res.json({
      success: true
    });
  } catch (e) {
    res.status(500).json({
      success: false
    });
  }
});

//app.use('/api/v1', apiV1Routes);

/**
* =================================================================================
* SEO & SITEMAPS
* =================================================================================
*/
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nAllow: /\nDisallow: /admin/\nDisallow: /search\nDisallow: /safelink\nDisallow: /player\nDisallow: /api/\nSitemap: ${SITE_URL}/sitemap_index.xml`);
});

app.get('/sitemap_index.xml', (req, res) => {
  const lastMod = new Date().toISOString().split('T')[0];
  const sitemaps = ['sitemap-static.xml',
    'sitemap-anime.xml',
    'sitemap-episode.xml',
    'sitemap-taxonomies.xml'];
  res.header('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${sitemaps.map(s => `<sitemap><loc>${SITE_URL}/${s}</loc><lastmod>${lastMod}</lastmod></sitemap>`).join('')}</sitemapindex>`);
});

app.get('/sitemap-static.xml', (req, res) => {
  const pages = [{
    url: '/',
    cf: 'monthly',
    p: '0.8'
  },
    {
      url: '/home',
      cf: 'daily',
      p: '1.0'
    },
    {
      url: '/anime-list',
      cf: 'daily',
      p: '0.9'
    },
    {
      url: '/genre-list',
      cf: 'weekly',
      p: '0.7'
    },
    {
      url: '/tahun-list',
      cf: 'yearly',
      p: '0.7'
    },
    {
      url: '/jadwal',
      cf: 'daily',
      p: '0.8'
    }];
  res.header('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${pages.map(p => `<url><loc>${SITE_URL}${p.url}</loc><lastmod>${new Date().toISOString().split('T')[0]}</lastmod><changefreq>${p.cf}</changefreq><priority>${p.p}</priority></url>`).join('')}</urlset>`);
});

app.get('/sitemap-anime.xml', async (req, res) => {
  res.header('Content-Type', 'application/xml');
  
  // 1. Tambahkan xmlns:image agar Google mengerti tag image
  res.write('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">');
  
  // 2. Tambahkan 'title' dan 'imageUrl' ke dalam query database
  const cursor = Anime.find({}, 'pageSlug title imageUrl updatedAt').lean().cursor();
  
  for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
    if (doc.pageSlug) {
      // Membersihkan karakter spesial pada judul agar XML tidak error (misal: & -> &amp;)
      const safeTitle = (doc.title || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');

      // Pastikan URL gambar absolut (ada domainnya)
      let imgUrl = doc.imageUrl || '/images/default.jpg';
      if (!imgUrl.startsWith('http')) {
        // Jika path relatif (/images/...), tambahkan SITE_URL
        imgUrl = `${SITE_URL}${imgUrl.startsWith('/') ? '' : '/'}${imgUrl}`;
      }

      const date = doc.updatedAt ? new Date(doc.updatedAt).toISOString().split('T')[0] : new Date().toISOString().split('T')[0];
      const loc = `${SITE_URL}/anime/${encodeURIComponent(doc.pageSlug)}`;

      // 3. Tulis struktur XML dengan Image
      // Gunakan satu baris string template untuk meminimalisir whitespace yang tidak perlu
      res.write(`<url><loc>${loc}</loc><lastmod>${date}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority><image:image><image:loc>${imgUrl}</image:loc><image:title>${safeTitle}</image:title></image:image></url>`);
    }
  }
  res.end('</urlset>');
});

app.get('/sitemap-episode.xml', async (req, res) => {
  res.header('Content-Type', 'application/xml');
  res.write('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
  const cursor = Episode.find({}, 'episodeSlug updatedAt').lean().cursor();
  for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
    if (doc.episodeSlug) res.write(`<url><loc>${SITE_URL}/episode/${doc.episodeSlug}</loc><lastmod>${doc.updatedAt ? new Date(doc.updatedAt).toISOString().split('T')[0]: new Date().toISOString().split('T')[0]}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`);
  }
  res.end('</urlset>');
});

app.get('/sitemap-taxonomies.xml', async (req, res) => {
  let [genres,
    types,
    studios,
    dates] = [appCache.get('allGenres'),
    appCache.get('allTypes'),
    appCache.get('allStudios'),
    appCache.get('allReleasedDates')];
  if (!genres) genres = await Anime.distinct('genres');
  if (!types) types = await Anime.distinct('info.Type');
  if (!studios) studios = await Anime.distinct('info.Studio');
  if (!dates) dates = await Anime.distinct('info.Released');

  const years = [...new Set(dates.map(d => d.match(/(\d{4})/) ? d.match(/(\d{4})/)[1]: null).filter(Boolean))];
  let xml = `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`;

  genres.forEach(g => xml += `<url><loc>${SITE_URL}/genre/${slugify(g)}</loc><changefreq>daily</changefreq><priority>0.7</priority></url>`);
  types.forEach(t => xml += `<url><loc>${SITE_URL}/type/${slugify(t)}</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>`);
  studios.forEach(s => xml += `<url><loc>${SITE_URL}/studio/${slugify(s)}</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>`);
  years.forEach(y => xml += `<url><loc>${SITE_URL}/tahun/${y}</loc><changefreq>yearly</changefreq><priority>0.6</priority></url>`);

  res.header('Content-Type', 'application/xml');
  res.send(xml + '</urlset>');
});

// --- Maintenance & 404 Pages ---
app.get('/maintenance', (req, res) => {
  res.render('maintenance', {
    page: 'maintenance', pageTitle: `Under Maintenance - ${SITE_NAME}`,
    pageDescription: 'Website sedang dalam perbaikan.', pageImage: '/images/default.jpg', pageUrl: SITE_URL + '/maintenance', query: ''
  });
});

app.use((req, res) => res.status(404).render('404', {
  page: '404', pageTitle: '404 Not Found', pageDescription: '', pageImage: '', pageUrl: '', query: ''
}));

/**
* =================================================================================
* SERVER START & DB CONNECTION
* =================================================================================
*/
if (!DB_URI) {
  console.error("FATAL: DB_URI missing in environment variables.");
  process.exit(1);
}

const startServer = async () => {
  try {
    await mongoose.connect(DB_URI, {
      serverSelectionTimeoutMS: 30000
    });
    console.log('[DB] Connected to MongoDB.');
    app.listen(PORT, () => console.log(`[SERVER] Running on port ${PORT}`));
  } catch (err) {
    console.error('[DB] Failed to connect.', err);
    process.exit(1);
  }
};

startServer();
