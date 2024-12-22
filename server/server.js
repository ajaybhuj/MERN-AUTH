import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
const app = express();
const port = process.env.PORT || 4000;

connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
  })
);
// API endpoints
app.use("/api/auth", authRouter);
app.get("/", (req, res) => {
  res.send("Welcome");
});

app.listen(port, () => {
  console.log(`listening on ${port}`);
});
