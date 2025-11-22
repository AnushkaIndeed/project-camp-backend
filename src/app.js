import express from "express";

import cors from "cors";

import cookieParser from "cookie-parser";

const app = express();

// Basic config
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));


app.use(cookieParser());

// CORS config
app.use(cors({
  origin: process.env.CORS_ORIGIN?.split(",") || "*",
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Authorization", "Content-Type"],
}));

// Preflight handler
app.options("/", cors());

// Routes
import healthCheckRouter from "./routes/healthcheck.routes.js";
import authRouter from "./routes/auth.routes.js";

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);
// Root route
app.get("/", (req, res) => {
  res.send("welcome to basecamp");
});

export default app;
