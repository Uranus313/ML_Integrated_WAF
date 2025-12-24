const express = require("express");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Root
app.get("/", (req, res) => {
  res.json({
    message: "Backend OK",
    ip: req.ip,
    headers: req.headers,
    query: req.query
  });
});

// Echo endpoint (useful for payload testing)
app.all("/echo", (req, res) => {
  res.json({
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    headers: req.headers
  });
});

// Fake login endpoint (for brute force / rate limit tests)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === "admin" && password === "admin") {
    return res.json({ success: true });
  }

  res.status(401).json({
    success: false,
    message: "Invalid credentials"
  });
});

// Endpoint with dynamic path (for traversal tests)
app.get("/files/:name", (req, res) => {
  res.json({
    requested: req.params.name
  });
});

// Catch-all
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
    path: req.path
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Test backend running on http://localhost:${PORT}`);
});
