const mongoose = require('mongoose');

const episodeSchema = new mongoose.Schema({
  episodeSlug: { type: String, unique: true, required: true, index: true },
  title: String,
  
  // Menyimpan nama server dan URL iframe
  streaming: [{ name: String, url: String }],
  
  // Menyimpan link download per kualitas
  downloads: [{
    quality: String, // Misal: "360p (40MB)"
    links: [{ host: String, url: String }]
  }],
  
  // Info Anime Induk (Untuk kemudahan navigasi/query)
  animeTitle: String,
  animeSlug: String,
  animeImageUrl: String,
  
  thumbnailUrl: String 
}, { timestamps: true });

module.exports = mongoose.model('Episode', episodeSchema);
