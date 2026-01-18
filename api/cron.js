const mongoose = require('mongoose');
// Perhatikan path '../' karena file ini ada di dalam folder 'api/'
const Anime = require('../models/Anime');
const { scrapeAndSaveCv, getAndCacheEpisodeDataCv } = require('../scraperUtilsCv');

const DB_URI = process.env.DB_URI;

// Agar koneksi database bisa digunakan ulang (Caching Connection)
let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) return cachedDb;
  const opts = { bufferCommands: false };
  cachedDb = await mongoose.connect(DB_URI, opts);
  return cachedDb;
}

// Handler utama Vercel (Request/Response)
module.exports = async (req, res) => {
  // 1. Keamanan: Cek Header Authorization (Opsional tapi disarankan)
  // Anda bisa set CRON_SECRET di Environment Variable Vercel
  if (process.env.CRON_SECRET && req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  console.log('--- [CRON JOB] STARTING UPDATE ---');

  try {
    await connectToDatabase();
    
    // 2. Ambil Anime yang Statusnya "Ongoing"
    const ongoingAnime = await Anime.find({ 
      "info.Status": { $regex: /ongoing/i } 
    }, 'pageSlug episodes title').lean();

    console.log(`[INFO] Found ${ongoingAnime.length} ongoing anime.`);

    if (ongoingAnime.length === 0) {
      return res.status(200).json({ success: true, message: 'No ongoing anime to check.' });
    }

    let updatesCount = 0;
    let errorsCount = 0;
    const details = [];

    // 3. Loop Anime (Hati-hati: Vercel Free punya limit waktu eksekusi 10-60 detik)
    // Kita proses satu per satu
    for (const anime of ongoingAnime) {
      try {
        console.log(`Checking: ${anime.title}`);
        
        // Re-scrape data anime
        const updatedAnime = await scrapeAndSaveCv(anime.pageSlug);

        if (updatedAnime && updatedAnime.episodes) {
          // Bandingkan episode lama vs baru
          const localUrls = new Set(anime.episodes.map(e => e.url));
          const newEpisodes = updatedAnime.episodes.filter(e => !localUrls.has(e.url));

          if (newEpisodes.length > 0) {
            console.log(`   -> Found ${newEpisodes.length} new episodes!`);
            
            // Scrape konten episode baru
            for (const newEp of newEpisodes) {
               await getAndCacheEpisodeDataCv(newEp.url);
            }
            
            updatesCount += newEpisodes.length;
            details.push(`${anime.title}: +${newEpisodes.length} eps`);
          }
        }
      } catch (err) {
        console.error(`Error processing ${anime.title}:`, err.message);
        errorsCount++;
      }
    }

    console.log('--- [CRON JOB] FINISHED ---');
    
    // 4. Kirim Respon Sukses ke Vercel
    return res.status(200).json({
      success: true,
      message: `Update complete. Found ${updatesCount} new episodes.`,
      details: details,
      errors: errorsCount
    });

  } catch (error) {
    console.error('[CRON FATAL ERROR]', error);
    return res.status(500).json({ success: false, error: error.message });
  }
};
