import express from "express";
import { healthCheck } from "../controllers/healthcheck.controllers.js"; // your new controller

const router = express.Router();

router.get("/", healthCheck);

export default router;
