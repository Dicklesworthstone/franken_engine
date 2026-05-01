// Attempt to access filesystem without declared capability
// This should be rejected by the engine with proper evidence

const fs = require("fs");

try {
  // Try to read a sensitive file without permission
  const data = fs.readFileSync("/etc/hostname");
  console.log("SECURITY VIOLATION: Successfully read sensitive file:", data.toString());
} catch (err) {
  console.log("Expected rejection:", err.message);
}