require("dotenv").config();
const { GoogleGenerativeAI } = require("@google/generative-ai");

const genAI = new GoogleGenerativeAI(process.env.GEMENI_API_KEY);

const generateDescription = async (transcript) => {
  try {
    if (!transcript || transcript.trim().length === 0) {
      return fallbackDescriptions();
    }

    const model = genAI.getGenerativeModel({
      model: "gemini-2.5-flash"
    });

    const prompt = `
You are an educational assistant.

Generate a detailed educational video description in:

- English
- Hindi
- Marathi
- Telugu
- Tamil

Return ONLY valid JSON in this exact format:

{
  "english": "...",
  "hindi": "...",
  "marathi": "...",
  "telugu": "...",
  "tamil": "..."
}

Do not add explanations.
Do not add markdown.
Do not wrap inside code blocks.

Transcript:
${transcript}
`;

    const result = await model.generateContent(prompt);
    const response = await result.response;

    let text = response.text().trim();

    // ===============================
    // CLEAN MARKDOWN FORMATTING
    // ===============================
    text = text
      .replace(/```json/gi, "")
      .replace(/```/g, "")
      .trim();

    // ===============================
    // EXTRACT JSON SAFELY
    // ===============================
    const jsonMatch = text.match(/\{[\s\S]*\}/);

    if (!jsonMatch) {
      console.error("No JSON object found in Gemini response");
      console.log("Raw Gemini Response:", text);
      return fallbackDescriptions();
    }

    const parsed = JSON.parse(jsonMatch[0]);

    // ===============================
    // VALIDATE REQUIRED KEYS
    // ===============================
    const requiredKeys = ["english", "hindi", "marathi", "telugu", "tamil"];

    for (const key of requiredKeys) {
      if (!parsed[key]) {
        console.warn(`Missing key in Gemini response: ${key}`);
        parsed[key] = fallbackDescriptions()[key];
      }
    }

    return parsed;

  } catch (error) {
    console.error("Gemini Description Error:", error.message);
    return fallbackDescriptions();
  }
};

// ===============================
// FALLBACK FUNCTION
// ===============================
const fallbackDescriptions = () => {
  return {
    english: "Description could not be generated.",
    hindi: "विवरण उत्पन्न नहीं हो सका।",
    marathi: "वर्णन तयार करता आले नाही.",
    telugu: "వివరణ సృష్టించబడలేదు.",
    tamil: "விளக்கம் உருவாக்க முடியவில்லை."
  };
};

module.exports = generateDescription;