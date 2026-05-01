// Proper declassification flow from confidential to public
// This should succeed with proper declassification receipt

console.log("Attempting confidential->public flow with declassification...");

try {
  // Simulate reading confidential data
  const confidentialData = "API performance metrics: /api/users/list 245ms avg";

  // Simulate declassification decision (this would create a signed receipt)
  const declassificationReceipt = {
    source_label: "confidential",
    sink_label: "public",
    authorized_by: "security_review_board",
    justification: "Performance metrics approved for public incident communication",
    timestamp: new Date().toISOString()
  };

  console.log("Declassification approved:", JSON.stringify(declassificationReceipt, null, 2));

  // After declassification, flow to public sink is allowed
  console.log("PUBLIC OUTPUT:", confidentialData);

  console.log("Flow completed successfully with proper declassification");
} catch (error) {
  console.log("Unexpected error:", error.message);
}