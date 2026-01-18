const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');
const qs = require('querystring');
const Anime = require('./models/Anime');
const Episode = require('./models/Episode');
const { GoogleAuth } = require('google-auth-library');

// --- KONFIGURASI ---
const BASE_URL = 'https://otakudesu.best'; 
const BASE_SCRAPE_URL_ANIME = `${BASE_URL}/anime/`; 
const BASE_SCRAPE_URL_EPISODE = `${BASE_URL}/episode/`;

const SITE_URL_FOR_INDEXING = process.env.SITE_URL || 'http://localhost:3000';
const INDEXING_API_ENDPOINT = 'https://indexing.googleapis.com/v3/urlNotifications:publish';
const INDEXING_SCOPES = ['https://www.googleapis.com/auth/indexing'];

const SCRAPER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
  'Referer': 'https://otakudesu.best/',
  'X-Requested-With': 'XMLHttpRequest',
  'Origin': 'https://otakudesu.best'
};

// ===================================
// --- HELPER FUNCTIONS ---
// ===================================

function decodeBase64(str) {
    try {
        return Buffer.from(str, 'base64').toString('utf-8');
    } catch (e) {
        return null;
    }
}

async function fetchNonce(nonceAction) {
    if (!nonceAction) return null;
    try {
        const postData = qs.stringify({ action: nonceAction });
        const response = await axios.post(`${BASE_URL}/wp-admin/admin-ajax.php`, postData, {
            headers: { ...SCRAPER_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        if (response.data && response.data.data) {
            return response.data.data;
        }
        return null;
    } catch (e) {
        return null;
    }
}

async function resolveMirrorLink(base64Content, streamAction, nonce) {
    if (!base64Content || !streamAction) return null;

    try {
        const jsonStr = decodeBase64(base64Content);
        const payload = JSON.parse(jsonStr);

        const body = {
            ...payload,
            action: streamAction
        };
        if (nonce) body.nonce = nonce;

        const postData = qs.stringify(body);

        const response = await axios.post(`${BASE_URL}/wp-admin/admin-ajax.php`, postData, {
            headers: { ...SCRAPER_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        if (response.data && response.data.data) {
            const iframeHtml = decodeBase64(response.data.data);
            const $ = cheerio.load(iframeHtml);
            const src = $('iframe').attr('src');
            return src || null;
        }
        return null;
    } catch (error) {
        return null;
    }
}

async function downloadImage(externalUrl, baseFilename, subfolder = '') {
  if (!externalUrl || !externalUrl.startsWith('http')) {
    return subfolder === 'episodes' ? '/images/default_thumb.jpg' : '/images/default.jpg';
  }
  try {
    const urlObject = new URL(externalUrl);
    let extension = path.extname(urlObject.pathname);
    if (!['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(extension.toLowerCase())) {
        extension = '.jpg';
    }
    const safeFilename = baseFilename.replace(/[^a-zA-Z0-9-_]/g, '-').substring(0, 100);
    const localFilename = `${safeFilename}${extension}`;
    const targetDir = path.join(__dirname, 'public', 'images', subfolder);
    const localDiskPath = path.join(targetDir, localFilename);
    const webPath = `/images/${subfolder ? subfolder + '/' : ''}${localFilename}`;

    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
    if (fs.existsSync(localDiskPath)) return webPath;

    const response = await axios({ url: externalUrl, method: 'GET', responseType: 'stream', headers: SCRAPER_HEADERS });
    const writer = fs.createWriteStream(localDiskPath);
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => resolve(webPath));
      writer.on('error', (err) => { fs.unlink(localDiskPath, () => {}); reject(err); });
    });
  } catch (error) {
    return subfolder === 'episodes' ? '/images/default_thumb.jpg' : '/images/default.jpg';
  }
}

async function notifyGoogleIndexing(pageSlug, requestType = 'URL_UPDATED') {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_CREDENTIALS) return;
    try {
        const credentials = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_CREDENTIALS);
        const auth = new GoogleAuth({ credentials, scopes: INDEXING_SCOPES });
        const authToken = await auth.getAccessToken();
        const urlToSubmit = `${SITE_URL_FOR_INDEXING}/anime/${encodeURIComponent(pageSlug)}`;
        const requestData = { url: urlToSubmit, type: requestType };
        await axios.post(INDEXING_API_ENDPOINT, requestData, { headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` } });
    } catch (error) { console.error('[Google Indexing] Error:', error.message); }
}

// ===================================
// --- ANIME DETAIL SCRAPER ---
// ===================================
async function scrapeAndSaveCv(pageSlug) {
  const encodedSlug = encodeURIComponent(pageSlug);
  const targetUrl = `${BASE_SCRAPE_URL_ANIME}${encodedSlug}/`;

  try {
    console.log(`[SCRAPER ANIME] Processing: ${pageSlug}`);
    const { data } = await axios.get(targetUrl, { headers: SCRAPER_HEADERS });
    const $ = cheerio.load(data);

    if (!$('.jdlrx h1').length && !$('.fotoanime').length) {
      console.warn(`[SCRAPER ANIME] Invalid content for ${pageSlug}. Skipped.`);
      return null;
    }

    const scrapedData = { info: {}, genres: [], episodes: [], characters: [], pageSlug: pageSlug };

    let rawTitle = $('.jdlrx h1').text().trim();
    scrapedData.title = rawTitle.replace(/Subtitle Indonesia/i, '').trim();

    const imgElement = $('.fotoanime img');
    const externalImageUrl = imgElement.attr('src');
    scrapedData.imageUrl = await downloadImage(externalImageUrl, pageSlug);

    $('.infozingle p').each((i, el) => {
        const spanText = $(el).find('span').text().trim(); 
        const parts = spanText.split(':');
        if (parts.length >= 2) {
            let key = parts[0].trim().replace(/<b>|<\/b>/g, '');
            let value = parts.slice(1).join(':').trim(); 

            if (key.toLowerCase() === 'japanese') scrapedData.info.Alternatif = value;
            if (key.toLowerCase() === 'tipe') scrapedData.info.Type = value;
            if (key.toLowerCase() === 'status') scrapedData.info.Status = value;
            if (key.toLowerCase() === 'total episode') scrapedData.info.Episode = value;
            if (key.toLowerCase() === 'durasi') scrapedData.info.Duration = value;
            if (key.toLowerCase() === 'tanggal rilis') scrapedData.info.Released = value;
            if (key.toLowerCase() === 'studio') scrapedData.info.Studio = value;
            if (key.toLowerCase() === 'produser') scrapedData.info.Producers = value;
            if (key.toLowerCase() === 'skor') scrapedData.info.Score = value;

            if (key.toLowerCase() === 'genre') {
                $(el).find('a').each((j, genreLink) => {
                    scrapedData.genres.push($(genreLink).text().trim());
                });
            }
        }
    });

    scrapedData.synopsis = $('.sinopc p').map((i, el) => $(el).text().trim()).get().join('\n\n');

    console.log(`[SCRAPER ANIME] Extracting episodes...`);
    $('.episodelist ul li').each((i, el) => {
        const anchor = $(el).find('a');
        const episodeUrl = anchor.attr('href');
        const episodeTitle = anchor.text().trim();
        const episodeDate = $(el).find('.zeebr').text().trim();

        if (episodeUrl && episodeUrl.includes('/episode/')) {
            const pathSegments = episodeUrl.split('/').filter(Boolean);
            const epSlug = pathSegments[pathSegments.length - 1];
            if (epSlug) {
                scrapedData.episodes.push({ title: episodeTitle, url: epSlug, date: episodeDate });
            }
        }
    });
    scrapedData.episodes.reverse();

    const animeDocument = await Anime.findOneAndUpdate({ pageSlug: pageSlug }, scrapedData, { new: true, upsert: true });
    if (animeDocument) { try { await notifyGoogleIndexing(pageSlug, 'URL_UPDATED'); } catch (e) {} }
    
    return animeDocument;
  } catch (error) {
    console.error(`[SCRAPER ANIME] Error processing ${pageSlug}:`, error.message);
    throw error;
  }
}

// ===================================
// --- EPISODE DETAIL SCRAPER ---
// ===================================
async function scrapeEpisodePageCv(episodeSlug) {
  const encodedSlug = encodeURIComponent(episodeSlug);
  const targetUrl = `${BASE_SCRAPE_URL_EPISODE}${encodedSlug}/`;

  try {
    const { data } = await axios.get(targetUrl, { headers: SCRAPER_HEADERS });
    const $ = cheerio.load(data);

    if (!$('.posttl').length) {
      return { title: episodeSlug, streaming: [], downloads: [], errorStatus: 404 };
    }

    const result = {
        title: $('.posttl').text().trim(),
        streaming: [],
        downloads: []
    };

    let nonceAction = null;
    let streamAction = null;

    $('script').each((i, el) => {
        const scriptContent = $(el).html();
        if (scriptContent && scriptContent.includes('admin-ajax.php')) {
            const matchNonce = scriptContent.match(/data\s*:\s*{\s*action\s*:\s*["']([a-zA-Z0-9]+)["']\s*}/);
            if (matchNonce) nonceAction = matchNonce[1];

            const matchStream = scriptContent.match(/nonce\s*:[^,]+,\s*action\s*:\s*["']([a-zA-Z0-9]+)["']/);
            if (matchStream) streamAction = matchStream[1];
        }
    });

    if (!streamAction && nonceAction) streamAction = nonceAction;

    let pageNonce = null;
    if (nonceAction) {
        pageNonce = await fetchNonce(nonceAction);
    }

    const mainIframeSrc = $('#pembed iframe').attr('src');
    if (mainIframeSrc) {
        result.streaming.push({ 
            name: 'Default', 
            url: mainIframeSrc, 
            quality: 'HD'
        });
    }

    const mirrorPromises = [];
    $('.mirrorstream ul').each((i, ul) => {
        let resolutionClass = $(ul).attr('class') || '';
        let quality = resolutionClass.replace('m', '').trim(); 

        $(ul).find('li a').each((j, link) => {
            const providerName = $(link).text().trim();
            const dataContent = $(link).attr('data-content'); 

            if (providerName && dataContent && streamAction) {
                mirrorPromises.push(async () => {
                    const resolvedUrl = await resolveMirrorLink(dataContent, streamAction, pageNonce);
                    if (resolvedUrl) {
                        return {
                            name: providerName,
                            url: resolvedUrl, 
                            quality: quality
                        };
                    }
                    return null;
                });
            }
        });
    });

    if (mirrorPromises.length > 0) {
        const resolvedMirrors = await Promise.all(mirrorPromises.map(p => p()));
        resolvedMirrors.forEach(mirror => {
            if (mirror) result.streaming.push(mirror);
        });
    }

    $('.download ul li').each((i, el) => {
        const qualityElem = $(el).find('strong');
        let quality = qualityElem.text().trim(); 
        const size = $(el).find('i').text().trim();
        if (size) quality += ` (${size})`;

        const links = [];
        $(el).find('a').each((j, linkEl) => {
            const host = $(linkEl).text().trim();
            const url = $(linkEl).attr('href');
            if (host && url && !url.includes('javascript:void')) {
                links.push({ host: host, url: url });
            }
        });

        if (quality && links.length > 0) {
            result.downloads.push({ quality: quality, links: links });
        }
    });

    const metaImg = $('meta[property="og:image"]').attr('content');
    if (metaImg) {
        result.thumbnailUrl = await downloadImage(metaImg, `thumb-${episodeSlug}`, 'episodes');
    }

    return result;

  } catch (error) {
    const status = error.response ? error.response.status : 500;
    console.error(`  [SCRAPER EP] Error ${episodeSlug}:`, error.message);
    return { title: episodeSlug, streaming: [], downloads: [], thumbnailUrl: '/images/default_thumb.jpg', errorStatus: status };
  }
}

// ===================================
// --- EPISODE CACHING FUNCTION (UPDATED) ---
// ===================================
async function getAndCacheEpisodeDataCv(episodeSlug) {
  try {
    let episodeData = await Episode.findOne({ episodeSlug: episodeSlug }).lean();
    let isUpdate = false;

    // --- LOGIKA BARU: Cek Kelengkapan Data ---
    if (episodeData) {
      // Jika data ada, tapi streaming kosong, kita anggap belum lengkap -> RE-SCRAPE
      if (!episodeData.streaming || episodeData.streaming.length === 0) {
          console.log(`  [CACHE] Found ${episodeSlug} but NO STREAMING links. Re-scraping...`);
          isUpdate = true; // Tandai sebagai update
      } else {
          // Data lengkap -> Skip
          // delete episodeData._id; delete episodeData.__v;
          return { status: 'skipped', data: episodeData };
      }
    } else {
        console.log(`  [CACHE] Miss for: ${episodeSlug}. Scraping new...`);
    }

    // Scrape data baru (atau update)
    const parentAnime = await Anime.findOne({ "episodes.url": episodeSlug }).select('title pageSlug imageUrl').lean();
    const scrapedData = await scrapeEpisodePageCv(episodeSlug);

    if (scrapedData.errorStatus && scrapedData.errorStatus !== 404) {
      return { status: 'failed', data: { ...scrapedData, episodeSlug: episodeSlug } };
    }

    const dataToSave = {
        ...scrapedData,
        episodeSlug: episodeSlug,
        animeTitle: parentAnime?.title || 'Unknown Anime',
        animeSlug: parentAnime?.pageSlug || null,
        animeImageUrl: parentAnime?.imageUrl || '/images/default.jpg'
    };

    // Gunakan findOneAndUpdate dengan upsert agar bisa menghandle Insert Baru maupun Update
    const savedEpisode = await Episode.findOneAndUpdate(
        { episodeSlug: episodeSlug },
        dataToSave,
        { new: true, upsert: true }
    );
    
    const savedDataObject = savedEpisode.toObject();
    delete savedDataObject._id; delete savedDataObject.__v;
    
    // Kembalikan status sesuai kondisi
    return { status: isUpdate ? 'updated' : 'success', data: savedDataObject };

  } catch (error) {
    console.error(`  [CACHE] Critical error for ${episodeSlug}:`, error.message);
    return { status: 'failed', data: { episodeSlug } };
  }
}

module.exports = {
  scrapeAndSaveCv,
  getAndCacheEpisodeDataCv
};
