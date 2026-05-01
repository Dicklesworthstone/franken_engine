// Attempt to flow confidential data to public sink without declassification
// This should be rejected by the IFC system

console.log("Attempting confidential->public flow without declassification...");

try {
  // Simulate reading confidential data (this would be labeled "Confidential")
  const confidentialData = "API performance metrics: /api/users/list 245ms avg";

  // Try to write to public output without declassification
  // This should trigger IFC violation
  console.log("PUBLIC OUTPUT:", confidentialData);

  console.log("ERROR: Flow should have been denied!");
} catch (error) {
  console.log("Expected IFC violation:", error.message);
}