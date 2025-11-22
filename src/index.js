import dotenv from "dotenv";
dotenv.config({ path: "./.env" });

import app from "./app.js";
import connectDB from "./database/index.js";

const port = parseInt(process.env.PORT, 10) || 8000;

// Connect to DB and start server
connectDB()
  .then(() => {
    app.listen(port, "0.0.0.0", () => {
  console.log(`✅ Server running on http://localhost:${port}`);
});

  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });
