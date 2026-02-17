const mongoose = require('mongoose');

const animeSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  pageSlug: { 
    type: String, 
    unique: true, 
    required: true, 
    index: true 
  },
  imageUrl: {
    type: String,
    default: '/images/default.jpg'
  },
  synopsis: String,
  
  // Update Info Schema agar fleksibel dengan data Otakudesu
  info: {
    Alternatif: { type: String, default: '' },
    Type: { type: String, default: '' },
    Episode: { type: String, default: '' },
    Status: { type: String, default: 'Unknown' },
    Released: { type: String, default: '' },
    Duration: { type: String, default: '' }, // Baru
    Score: { type: String, default: '' },    // Baru
    Studio: { type: String, default: '' },
    Producers: { type: String, default: '' }
  },

  genres: [String],
  
  // List Episode (Hanya referensi slug & judul)
  episodes: [{
    title: String, 
    url: String,   // Slug Episode
    date: String,
  }],

  viewCount: {
    type: Number,
    default: 0, 
    index: true 
  }
}, { timestamps: true });

module.exports = mongoose.model('Anime', animeSchema);
