const generateDescription = require("../services/generateDescription");
const createMultiDescriptionFiles = require("../services/createMultiDescriptionFiles");
const uploadTextFile = require("../services/uploadTextToImagekit");
const { uploadVideo, uploadFile } = require("../services/imagekitUpload");
const generateUrls = require("../services/videoTransformService");
const Video = require("../models/Video");
const fs = require("fs");
const path = require("path");
const extractAudio = require("../services/extractAudio");
const transcribeAudio = require("../services/transcribeAudio");
const generateQuiz = require("../services/generateQuiz");

exports.uploadVideoByAdmin = async (req, res) => {
  let videoPath = null;
  let audioPath = null;
  let descFilePaths = {};

  try {
    const { courseId, title, textContent, order, notes } = req.body;

    // =========================
    // Check video file
    // =========================
    if (!req.files || !req.files.video) {
      return res.status(400).json({ message: "Video file required" });
    }

    videoPath = req.files.video[0].path;

    // =========================
    // 1️⃣ Upload Video
    // =========================
    const fileData = await uploadVideo(videoPath);
    const videoUrl = fileData.url;
    console.log("Video uploaded to ImageKit");

    // =========================
    // 2️⃣ Extract Audio
    // =========================
    audioPath = await extractAudio(videoPath);
    console.log("Audio extracted");

    // =========================
    // 3️⃣ Transcribe Audio
    // =========================
    const transcript = await transcribeAudio(audioPath);
    console.log("Transcript generated");

    // =========================
    // 4️⃣ Generate 5-Language Description
    // =========================
    const descriptions = await generateDescription(transcript);
    console.log("Multilingual descriptions generated");

    // =========================
    // 5️⃣ Generate Quiz
    // =========================
    const quiz = await generateQuiz(transcript);
    console.log("Quiz generated:", quiz.length);

    // =========================
    // 6️⃣ Create 5 TXT Files
    // =========================
    descFilePaths = createMultiDescriptionFiles(descriptions);

    // =========================
    // 7️⃣ Upload Description Files
    // =========================
    let descriptionUrls = {};

    for (const lang in descFilePaths) {
      const uploadedUrl = await uploadTextFile(descFilePaths[lang]);
      descriptionUrls[lang] = uploadedUrl;

      // Delete local txt file (uploadTextFile already deletes the file; this is a safe no-op)
      deleteLocalFile(descFilePaths[lang]);
    }

    console.log("All description files uploaded");

    // =========================
    // 8️⃣ Upload Attachments
    // =========================
    let attachments = [];

    if (req.files && req.files.files) {
      console.log("Attachments found");

      for (const file of req.files.files) {
        const uploaded = await uploadFile(file.path);
        attachments.push(uploaded);

        deleteLocalFile(file.path);
      }
    }

    // =========================
    // 9️⃣ Generate Resolution URLs
    // =========================
    const resolutions = generateUrls(videoUrl);

    // =========================
    // 🔟 Save to MongoDB
    // =========================
    const video = new Video({
      courseId,
      title,
      textContent,
      notes,
      publicId: fileData.fileId,
      url: videoUrl,
      downloadUrl: fileData.downloadUrl,
      attachments,
      quiz,
      descriptionUrls: {
        english: descriptionUrls.english || "",
        hindi: descriptionUrls.hindi || "",
        marathi: descriptionUrls.marathi || "",
        telugu: descriptionUrls.telugu || "",
        tamil: descriptionUrls.tamil || ""
        }, // 🔥 5 language URLs
      size: fileData.size,
      resolutions,
      order
    });

    await video.save();
    console.log("Video saved in DB");

    // =========================
    // Cleanup local files
    // =========================
    deleteLocalFile(videoPath);
    deleteLocalFile(audioPath);

    res.status(200).json({
      message: "Video uploaded successfully",
      video
    });

  } catch (err) {
    console.error("Upload Pipeline Error:", err);

    deleteLocalFile(videoPath);
    deleteLocalFile(audioPath);

    Object.values(descFilePaths).forEach(deleteLocalFile);

    res.status(500).json({ error: err.message });
  }
};

// =========================
// Safe Delete Function
// =========================
const deleteLocalFile = (filePath) => {
  try {
    if (!filePath) return;

    const absolutePath = path.resolve(filePath);

    if (fs.existsSync(absolutePath)) {
      fs.unlinkSync(absolutePath);
      console.log("Deleted:", absolutePath);
    }
  } catch (err) {
    console.error("Delete error:", err.message);
  }
};