const mongoose = require("mongoose");

const attachmentSchema = new mongoose.Schema({
  fileId: String,
  fileName: String,
  fileUrl: String,
  downloadUrl: String,
  fileType: String,
  size: Number
});

const questionSchema = new mongoose.Schema({
  question: String,
  options: [String],
  correctAnswer: Number   // index of correct option (0-3)
});

const videoSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },

  title: String,

  textContent: String,

  attachments: [attachmentSchema],

  quiz: [questionSchema],

  publicId: String,
  
  url: String,

  downloadUrl: String,

  size: Number,
  duration: Number,
  originalResolution: String,
  width: Number,
  height: Number,

  resolutions: {
    p240: String,
    p360: String,
    p720: String
  },

  descriptionUrls: {
    english: String,
    hindi: String,
    marathi: String,
    telugu: String,
    tamil: String
  },
  
  order: Number,

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Video", videoSchema);
